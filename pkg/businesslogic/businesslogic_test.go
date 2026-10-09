package businesslogic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 1. Test Workflow Modeling & Discovery
func TestWorkflowModeling(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(nil, DefaultConfig())

	// Case A: Discovered endpoints representing a checkout flow
	endpoints := []DiscoveredEndpoint{
		{Method: "POST", Path: "/cart/add", Type: "cart"},
		{Method: "POST", Path: "/checkout/address", Type: "step"},
		{Method: "POST", Path: "/checkout/shipping", Type: "step"},
		{Method: "POST", Path: "/checkout/payment", Type: "pay"},
		{Method: "POST", Path: "/checkout/fulfill", Type: "download"},
	}

	actx := &AssessmentContext{
		AssessmentID: "asm-model-1",
		BaseURL:      "https://app.example.com",
		Endpoints:    endpoints,
	}

	workflows := engine.ModelWorkflows(ctx, actx)
	if len(workflows) == 0 {
		t.Fatal("expected at least one modeled workflow, got 0")
	}

	foundOrder := false
	for _, wf := range workflows {
		if wf.ID == "WF-ECOMMERCE-ORDER" {
			foundOrder = true
			if len(wf.Steps) < 3 {
				t.Errorf("expected checkout workflow to have >=3 steps, got %d", len(wf.Steps))
			}
			if len(wf.AllowedTransitions) == 0 {
				t.Errorf("expected transitions to be modeled for checkout workflow")
			}
		}
	}
	if !foundOrder {
		t.Error("expected WF-ECOMMERCE-ORDER workflow to be discovered")
	}

	// Case B: Fallback default workflows when endpoints are empty
	emptyCtx := &AssessmentContext{
		AssessmentID: "asm-model-empty",
		BaseURL:      "https://api.example.com",
	}
	defaultWfs := engine.ModelWorkflows(ctx, emptyCtx)
	if len(defaultWfs) < 2 {
		t.Fatalf("expected default modeled workflows on empty context, got %d", len(defaultWfs))
	}

	// Case C: Explicit workflows supplied by operator
	customWf := Workflow{
		ID:          "custom-approval",
		Name:        "Custom Document Approval",
		Description: "Multi-party approval workflow",
		Steps: []WorkflowStep{
			{Index: 1, Name: "Draft", Endpoint: "/docs/draft", Method: "POST"},
			{Index: 2, Name: "Review", Endpoint: "/docs/review", Method: "POST", Prerequisites: []string{"draft_submitted"}},
			{Index: 3, Name: "Approve", Endpoint: "/docs/approve", Method: "POST", Prerequisites: []string{"reviewed"}},
		},
	}
	customCtx := &AssessmentContext{
		AssessmentID: "asm-model-custom",
		BaseURL:      "https://api.example.com",
		Workflows:    []Workflow{customWf},
	}
	customResult := engine.ModelWorkflows(ctx, customCtx)
	if len(customResult) != 1 || customResult[0].ID != "custom-approval" {
		t.Errorf("expected explicit workflow to be preserved verbatim")
	}
}

// 2. Test Plan Generation & Prerequisites
func TestEngine_Plan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowStateChanging = true
	engine := NewEngine(nil, cfg)

	// Context with multiple workflows and identities
	actx := &AssessmentContext{
		AssessmentID: "asm-plan-1",
		BaseURL:      "https://app.example.com",
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/cart/add", Type: "cart"},
			{Method: "POST", Path: "/checkout/pay", Type: "pay"},
		},
		Identities: []TestIdentity{
			{ID: "id-1", Role: "buyer", PrivilegeLevel: 1},
			{ID: "id-2", Role: "seller", PrivilegeLevel: 2},
		},
	}

	plan, err := engine.Plan(context.Background(), actx)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if plan.TotalPlannedChecks == 0 {
		t.Fatal("expected planned checks > 0")
	}
	if plan.ReadyChecks == 0 {
		t.Fatal("expected ready checks > 0")
	}

	// Verify all 8 categories are represented in metadata
	for _, cat := range AllCategories() {
		meta, ok := CategoryMetadata[cat]
		if !ok {
			t.Errorf("missing CategoryMetadata for %s", cat)
		}
		if meta.CWE == "" || meta.WSTG == "" {
			t.Errorf("missing CWE or WSTG for %s", cat)
		}
	}
}

// 3. Test Redaction and Sanitization Helpers
func TestRedactionAndSanitization(t *testing.T) {
	// Bearer tokens and JWTs
	inputToken := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
	redactedToken := RedactText(inputToken)
	if strings.Contains(redactedToken, "doNotLeakThisSignature") {
		t.Errorf("RedactText failed to redact JWT: %s", redactedToken)
	}

	// Credit card numbers
	inputCard := "Charged card 4111-2222-3333-4444 successfully"
	redactedCard := RedactText(inputCard)
	if strings.Contains(redactedCard, "4111") {
		t.Errorf("RedactText failed to redact card: %s", redactedCard)
	}

	// Secret query parameters in URL
	rawURL := "https://api.example.com/checkout?token=secret123&session=user99&key=apikey456"
	sanitized := SanitizeURL(rawURL)
	if strings.Contains(sanitized, "secret123") || strings.Contains(sanitized, "apikey456") {
		t.Errorf("SanitizeURL failed to strip secrets: %s", sanitized)
	}

	// Hash identifier
	h1 := HashIdentifier("sensitive_flow_123")
	h2 := HashIdentifier("sensitive_flow_123")
	h3 := HashIdentifier("different_flow_456")
	if h1 != h2 {
		t.Errorf("expected deterministic hash for same identifier")
	}
	if h1 == h3 {
		t.Errorf("expected different hash for different identifier")
	}
}

// 4. Test BL-01: Workflow Circumvention (Skipped Steps)
func TestCategoryBL01_WorkflowCircumvention(t *testing.T) {
	t.Run("Negative_PrerequisiteEnforced", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"order_session_required","message":"Must complete step 1 before payment"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "asm-bl01-proper",
			BaseURL:      ts.URL,
			Workflows: []Workflow{{
				ID: "WF-01", Name: "Fulfillment Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Cart", Endpoint: "/cart/add", Method: "POST"},
					{Index: 2, Name: "Fulfill", Endpoint: "/checkout/fulfill", Method: "POST", VerificationEligible: true, Prerequisites: []string{"Payment"}},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}
		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}
		cov := summary.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-01, got %+v", cov)
		}
	})

	t.Run("Positive_VulnerableCircumvention", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success","order_id":"12345","state":"PAID"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl01-vuln",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-01", Name: "Fulfillment Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Cart", Endpoint: "/cart/add", Method: "POST"},
					{Index: 2, Name: "Fulfill", Endpoint: "/checkout/fulfill", Method: "POST", VerificationEligible: true, Prerequisites: []string{"Payment"}},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}
		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}
		cov := summary.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-01, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedOutcome", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"received"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl01-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-01", Name: "Fulfillment Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Cart", Endpoint: "/cart/add", Method: "POST"},
					{Index: 2, Name: "Fulfill", Endpoint: "/checkout/fulfill", Method: "POST", VerificationEligible: true, Prerequisites: []string{"Payment"}},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}
		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}
		cov := summary.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous BL-01, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success","order_id":"12345","state":"PAID"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl01-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-01", Name: "Inferred Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Cart", Endpoint: "/cart/add", Method: "POST"},
					{Index: 2, Name: "Fulfill", Endpoint: "/checkout/fulfill", Method: "POST", VerificationEligible: true, Prerequisites: []string{"Payment"}},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}
		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}
		cov := summary.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-01, got %+v", cov)
		}
	})
}

// 5. Test BL-02: Unexpected State Transitions & Safety Gating
func TestCategoryBL02_UnexpectedStateTransitions(t *testing.T) {
	t.Run("SafetyGating_DefaultBlocked", func(t *testing.T) {
		cfgSafe := DefaultConfig()
		cfgSafe.AllowStateChanging = false
		engineSafe := NewEngine(nil, cfgSafe)

		actxSafe := &AssessmentContext{
			AssessmentID: "asm-bl02-safe",
			BaseURL:      "http://127.0.0.1:18080",
			Workflows: []Workflow{{
				ID: "WF-02", Name: "Order Transition Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transition", Endpoint: "/order/transition", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summarySafe, err := engineSafe.Assess(context.Background(), actxSafe)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		covSafe := summarySafe.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
		if covSafe.Blocked == 0 {
			t.Errorf("expected AllowStateChanging=false to record Blocked for BL-02, got %+v", covSafe)
		}
	})

	t.Run("Positive_ProhibitedTransitionPermitted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"COMPLETED","state":"COMPLETED","order_id":"ORD-1"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl02-active",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-02", Name: "Order Transition Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transition", Endpoint: "/order/transition", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
		if cov.Verified == 0 {
			t.Errorf("expected synthetic fixture to record VERIFIED for BL-02, got %+v", cov)
		}
	})

	t.Run("Negative_TransitionRejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"prohibited_state_transition"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl02-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-02", Name: "Order Transition Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transition", Endpoint: "/order/transition", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-02, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedTransition", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"acknowledged":true}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl02-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-02", Name: "Order Transition Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transition", Endpoint: "/order/transition", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous transition in BL-02, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"COMPLETED"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl02-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-02", Name: "Inferred Transition Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transition", Endpoint: "/order/transition", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-02, got %+v", cov)
		}
	})
}

// 6. Test BL-03: State Manipulation & Parameter Integrity
func TestCategoryBL03_StateManipulation(t *testing.T) {
	t.Run("Positive_ClientPriceOverrideAccepted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"PAID","price":0.01,"total_charged":0.01}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl03-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-03", Name: "Pricing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Update Cart", Endpoint: "/cart/update", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-03, got %+v", cov)
		}
	})

	t.Run("Negative_ClientOverrideRejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"cannot_modify_price"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl03-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-03", Name: "Pricing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Update Cart", Endpoint: "/cart/update", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-03, got %+v", cov)
		}
	})

	t.Run("Negative_ClientOverrideIgnored", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"UNPAID","total":199.99,"recalculated":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl03-ignored",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-03", Name: "Pricing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Update Cart", Endpoint: "/cart/update", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for ignored override in BL-03, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedManipulation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl03-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-03", Name: "Pricing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Update Cart", Endpoint: "/cart/update", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous manipulation in BL-03, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"PAID","price":0.01}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl03-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-03", Name: "Inferred Pricing Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Update Cart", Endpoint: "/cart/update", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-03, got %+v", cov)
		}
	})
}

// 7. Test BL-04: Unauthorized Workflow Access
func TestCategoryBL04_UnauthorizedWorkflowAccess(t *testing.T) {
	t.Run("Precondition_MissingIdentities_Inconclusive", func(t *testing.T) {
		engine := NewEngine(nil, DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl04-no-ids",
			BaseURL:          "https://example.com",
			SyntheticFixture: false,
			Identities:       nil,
			Workflows: []Workflow{{
				ID: "WF-04", Name: "Approval Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Approve", Endpoint: "/admin/approve", Method: "POST", RequiredRole: "admin"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
		if cov.Inconclusive == 0 {
			t.Errorf("expected INCONCLUSIVE for missing identities in BL-04, got %+v", cov)
		}
	})

	t.Run("Positive_ViewerRoleApproves", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"action":"approved","status":"APPROVED","success":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl04-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-1", Role: "viewer", PrivilegeLevel: 1},
				{ID: "user-2", Role: "approver", PrivilegeLevel: 3},
			},
			Workflows: []Workflow{{
				ID: "WF-04", Name: "Approval Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Approve", Endpoint: "/admin/approve", Method: "POST", RequiredRole: "approver"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-04, got %+v", cov)
		}
	})

	t.Run("Negative_ViewerRoleDenied", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"access_denied_role_viewer"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl04-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-1", Role: "viewer", PrivilegeLevel: 1},
				{ID: "user-2", Role: "approver", PrivilegeLevel: 3},
			},
			Workflows: []Workflow{{
				ID: "WF-04", Name: "Approval Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Approve", Endpoint: "/admin/approve", Method: "POST", RequiredRole: "approver"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-04, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedApproval", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"logged_for_review"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl04-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-1", Role: "viewer", PrivilegeLevel: 1},
				{ID: "user-2", Role: "approver", PrivilegeLevel: 3},
			},
			Workflows: []Workflow{{
				ID: "WF-04", Name: "Approval Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Approve", Endpoint: "/admin/approve", Method: "POST", RequiredRole: "approver"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous response in BL-04, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"action":"approved","success":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl04-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-1", Role: "viewer", PrivilegeLevel: 1},
				{ID: "user-2", Role: "approver", PrivilegeLevel: 3},
			},
			Workflows: []Workflow{{
				ID: "WF-04", Name: "Inferred Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Approve", Endpoint: "/admin/approve", Method: "POST", RequiredRole: "approver"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-04, got %+v", cov)
		}
	})
}

// 8. Test BL-05: Sensitive Business-Flow Abuse
func TestCategoryBL05_SensitiveFlowAbuse(t *testing.T) {
	t.Run("Positive_RepeatedRedemptionAllowed", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"discount":"applied","success":true,"credit":50}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl05-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-05", Name: "Promo Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Redeem Coupon", Endpoint: "/coupon/redeem", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategorySensitiveFlowAbuse)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-05, got %+v", cov)
		}
	})

	t.Run("Negative_RateLimitedOrSingleUse", func(t *testing.T) {
		reqCount := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount++
			if reqCount == 1 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"discount":"applied"}`))
			} else {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate_limit_exceeded"}`))
			}
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl05-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-05", Name: "Promo Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Redeem Coupon", Endpoint: "/coupon/redeem", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategorySensitiveFlowAbuse)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-05, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedBenefit", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"attempt":"recorded"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl05-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-05", Name: "Promo Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Redeem Coupon", Endpoint: "/coupon/redeem", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategorySensitiveFlowAbuse)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous response in BL-05, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"discount":"applied","success":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl05-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-05", Name: "Inferred Promo Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Redeem Coupon", Endpoint: "/coupon/redeem", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategorySensitiveFlowAbuse)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-05, got %+v", cov)
		}
	})
}

// 9. Test BL-06: Replay & Idempotency Flaws
func TestCategoryBL06_ReplayAndIdempotency(t *testing.T) {
	t.Run("SafetyGating_DefaultBlocked", func(t *testing.T) {
		cfgSafe := DefaultConfig()
		cfgSafe.AllowStateChanging = false
		engineSafe := NewEngine(nil, cfgSafe)

		actxSafe := &AssessmentContext{
			AssessmentID: "asm-bl06-safe",
			BaseURL:      "http://127.0.0.1:18080",
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Transfer Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summarySafe, err := engineSafe.Assess(context.Background(), actxSafe)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		covSafe := summarySafe.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if covSafe.Blocked == 0 {
			t.Errorf("expected AllowStateChanging=false to record Blocked for BL-06, got %+v", covSafe)
		}
	})

	t.Run("Positive_DuplicateTransactionCreated", func(t *testing.T) {
		seenKeys := make(map[string]bool)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key != "" {
				if seenKeys[key] {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status":"duplicate","new_transaction":true,"transaction_id":"tx-2"}`))
					return
				}
				seenKeys[key] = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"created","transaction_id":"tx-1"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl06-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Transfer Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-06, got %+v", cov)
		}
	})

	t.Run("Negative_ConflictRejected", func(t *testing.T) {
		seenKeys := make(map[string]bool)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key != "" {
				if seenKeys[key] {
					w.WriteHeader(http.StatusConflict)
					w.Write([]byte(`{"error":"duplicate_request_idempotency_key_reused"}`))
					return
				}
				seenKeys[key] = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"created","transaction_id":"tx-1"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl06-neg-conflict",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Transfer Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-06 conflict rejection, got %+v", cov)
		}
	})

	t.Run("Negative_IdempotentCachedResponse", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","idempotent":true,"tx":"tx-1"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl06-neg-cached",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Transfer Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for idempotent cached response in BL-06, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedReplay", func(t *testing.T) {
		seenKeys := make(map[string]bool)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key != "" {
				if seenKeys[key] {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"attempt":"second"}`))
					return
				}
				seenKeys[key] = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"attempt":"first"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl06-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Transfer Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous replay in BL-06, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		seenKeys := make(map[string]bool)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key != "" {
				if seenKeys[key] {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status":"duplicate"}`))
					return
				}
				seenKeys[key] = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"created"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		cfgActive := DefaultConfig()
		cfgActive.AllowStateChanging = true
		engine := NewEngine(ts.Client(), cfgActive)

		actx := &AssessmentContext{
			AssessmentID:     "asm-bl06-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-06", Name: "Inferred Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Transfer", Endpoint: "/account/transfer", Method: "POST", IsStateChanging: true},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryReplayIdempotency)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-06, got %+v", cov)
		}
	})
}

// 10. Test BL-07: Privilege & State Inconsistency
func TestCategoryBL07_PrivilegeStateInconsistency(t *testing.T) {
	t.Run("Precondition_MissingIdentities_Inconclusive", func(t *testing.T) {
		engine := NewEngine(nil, DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl07-no-ids",
			BaseURL:          "https://example.com",
			SyntheticFixture: false,
			Identities:       nil,
			Workflows: []Workflow{{
				ID: "WF-07", Name: "Publishing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Publish", Endpoint: "/resource/publish", Method: "POST", RequiredRole: "publisher"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
		if cov.Inconclusive == 0 {
			t.Errorf("expected INCONCLUSIVE for missing identities in BL-07, got %+v", cov)
		}
	})

	t.Run("Positive_SuspendedAccountPerformsOperation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"published","active":true,"success":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl07-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-suspended", Role: "suspended_user", PrivilegeLevel: 1, IsSuspended: true},
				{ID: "user-admin", Role: "admin", PrivilegeLevel: 5},
			},
			Workflows: []Workflow{{
				ID: "WF-07", Name: "Publishing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Publish", Endpoint: "/resource/publish", Method: "POST", RequiredRole: "publisher"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-07, got %+v", cov)
		}
	})

	t.Run("Negative_SuspendedAccountBlocked", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"account_suspended"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl07-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-suspended", Role: "suspended_user", PrivilegeLevel: 1, IsSuspended: true},
				{ID: "user-admin", Role: "admin", PrivilegeLevel: 5},
			},
			Workflows: []Workflow{{
				ID: "WF-07", Name: "Publishing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Publish", Endpoint: "/resource/publish", Method: "POST", RequiredRole: "publisher"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-07, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedOperation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"queued"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl07-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-suspended", Role: "suspended_user", PrivilegeLevel: 1, IsSuspended: true},
				{ID: "user-admin", Role: "admin", PrivilegeLevel: 5},
			},
			Workflows: []Workflow{{
				ID: "WF-07", Name: "Publishing Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Publish", Endpoint: "/resource/publish", Method: "POST", RequiredRole: "publisher"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous operation in BL-07, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"published"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl07-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Identities: []TestIdentity{
				{ID: "user-suspended", Role: "suspended_user", PrivilegeLevel: 1, IsSuspended: true},
				{ID: "user-admin", Role: "admin", PrivilegeLevel: 5},
			},
			Workflows: []Workflow{{
				ID: "WF-07", Name: "Inferred Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Publish", Endpoint: "/resource/publish", Method: "POST", RequiredRole: "publisher"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-07, got %+v", cov)
		}
	})
}

// 11. Test BL-08: Business Data Validation & Invariants
func TestCategoryBL08_BusinessDataValidation(t *testing.T) {
	t.Run("Positive_NegativeQuantityReverseCreditAccepted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success","total":-500,"credited":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl08-pos",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-08", Name: "Order Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Checkout", Endpoint: "/cart/checkout", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryDataValidationInvariants)]
		if cov.Verified == 0 {
			t.Errorf("expected VERIFIED for BL-08, got %+v", cov)
		}
	})

	t.Run("Negative_NegativeQuantityRejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"quantity_must_be_positive"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl08-neg",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-08", Name: "Order Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Checkout", Endpoint: "/cart/checkout", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryDataValidationInvariants)]
		if cov.NotVulnerable == 0 {
			t.Errorf("expected NOT_VULNERABLE for BL-08, got %+v", cov)
		}
	})

	t.Run("Ambiguity_UnconfirmedDataViolation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"cart_id":"123"}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl08-ambig",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-08", Name: "Order Flow", EvidenceSource: SourceObservedFact,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Checkout", Endpoint: "/cart/checkout", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryDataValidationInvariants)]
		if cov.Candidates == 0 {
			t.Errorf("expected CANDIDATE for ambiguous invariant response in BL-08, got %+v", cov)
		}
	})

	t.Run("Hypothesis_RemainsCandidate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"total":-500,"credited":true}`))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID:     "asm-bl08-hyp",
			BaseURL:          ts.URL,
			SyntheticFixture: true,
			Workflows: []Workflow{{
				ID: "WF-08", Name: "Inferred Flow", EvidenceSource: SourceInferredHypothesis,
				Steps: []WorkflowStep{
					{Index: 1, Name: "Checkout", Endpoint: "/cart/checkout", Method: "POST"},
				},
			}},
			IsAllowed: func(u string) bool { return true },
		}

		_, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov := summary.CategoryCoverageMap[string(CategoryDataValidationInvariants)]
		if cov.Candidates == 0 || cov.Verified > 0 {
			t.Errorf("expected CANDIDATE (never VERIFIED) for inferred hypothesis in BL-08, got %+v", cov)
		}
	})
}

// 12. Test Redirect Scope Enforcement
func TestRedirectScopeEnforcement(t *testing.T) {
	// Set up an out-of-scope redirection destination
	outOfScopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("out-of-scope destination reached!"))
	}))
	defer outOfScopeServer.Close()

	// In-scope server that redirects to out-of-scope server
	inScopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScopeServer.URL+"/evil", http.StatusFound)
	}))
	defer inScopeServer.Close()

	engine := NewEngine(nil, DefaultConfig())

	// Scope callback permits inScopeServer, but forbids outOfScopeServer
	actx := &AssessmentContext{
		AssessmentID: "asm-redirect-test",
		BaseURL:      inScopeServer.URL,
		Endpoints: []DiscoveredEndpoint{
			{Method: "GET", Path: "/redirect"},
		},
		IsAllowed: func(u string) bool {
			return strings.HasPrefix(u, inScopeServer.URL)
		},
		IsExcluded: func(u string) bool {
			return strings.HasPrefix(u, outOfScopeServer.URL)
		},
	}

	client := engine.scopedClient(actx)
	req, err := http.NewRequestWithContext(context.Background(), "GET", inScopeServer.URL+"/redirect", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	// Must fail because redirect to outOfScopeServer is blocked
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected redirect to out-of-scope target to be rejected, but request succeeded")
	}

	if !strings.Contains(err.Error(), "scope") {
		t.Errorf("expected redirect rejection error mentioning scope, got: %v", err)
	}
}

// 13. Test Synthetic Fixture Labeling
func TestSyntheticFixtureLabeling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"order_status":"COMPLETED"}`))
	}))
	defer ts.Close()

	engine := NewEngine(ts.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-synth-fixture",
		BaseURL:          ts.URL,
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/step1", Type: "step"},
			{Method: "POST", Path: "/order/pay", Type: "pay"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	if !summary.SyntheticFixture {
		t.Errorf("expected summary.SyntheticFixture to be true")
	}

	if len(findings) == 0 {
		t.Fatalf("expected at least one finding from synthetic fixture assessment")
	}

	// Verify findings have synthetic fixture annotation
	for _, f := range findings {
		if f.EvidenceDetails.Details["synthetic_fixture"] != "true" {
			t.Errorf("expected finding to contain synthetic_fixture detail annotation")
		}
	}
}
