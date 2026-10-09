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
	// Scenario A: Server properly enforces prerequisites (rejects terminal step with 400 Bad Request)
	tsProper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"order_session_required","message":"Must complete step 1 before payment"}`))
	}))
	defer tsProper.Close()

	engine := NewEngine(tsProper.Client(), DefaultConfig())
	actxProper := &AssessmentContext{
		AssessmentID: "asm-bl01-proper",
		BaseURL:      tsProper.URL,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/step1", Type: "step"},
			{Method: "POST", Path: "/order/pay", Type: "pay"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summary, err := engine.Assess(context.Background(), actxProper)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov01 := summary.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
	if cov01.NotVulnerable == 0 {
		t.Errorf("expected properly enforced flow to record NOT_VULNERABLE for BL-01, got %+v", cov01)
	}

	// Scenario B: Server improperly accepts terminal step out of order (returns 200 in synthetic fixture)
	tsVulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","order_id":"12345","state":"PAID"}`))
	}))
	defer tsVulnerable.Close()

	engineVuln := NewEngine(tsVulnerable.Client(), DefaultConfig())
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-bl01-vuln",
		BaseURL:          tsVulnerable.URL,
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/step1", Type: "step"},
			{Method: "POST", Path: "/order/pay", Type: "pay"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summaryVuln, err := engineVuln.Assess(context.Background(), actxVuln)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	covVuln := summaryVuln.CategoryCoverageMap[string(CategoryWorkflowCircumvention)]
	if covVuln.Verified == 0 {
		t.Errorf("expected vulnerable workflow circumvention in synthetic fixture to record VERIFIED, got %+v", covVuln)
	}
}

// 5. Test BL-02: Unexpected State Transitions & Safety Gating
func TestCategoryBL02_UnexpectedStateTransitions(t *testing.T) {
	// Scenario A: Read-only mode (AllowStateChanging = false) -> MUST record BLOCKED_BY_SAFETY
	cfgSafe := DefaultConfig()
	cfgSafe.AllowStateChanging = false
	engineSafe := NewEngine(nil, cfgSafe)

	actxSafe := &AssessmentContext{
		AssessmentID: "asm-bl02-safe",
		BaseURL:      "http://127.0.0.1:18080",
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/init", Type: "step"},
			{Method: "POST", Path: "/order/ship", Type: "terminal"},
		},
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

	// Scenario B: Synthetic fixture verification
	engineActive := NewEngine(nil, DefaultConfig())
	actxActive := &AssessmentContext{
		AssessmentID:     "asm-bl02-active",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/init", Type: "step"},
			{Method: "POST", Path: "/order/ship", Type: "terminal"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summaryActive, err := engineActive.Assess(context.Background(), actxActive)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	covActive := summaryActive.CategoryCoverageMap[string(CategoryUnexpectedStateTransition)]
	if covActive.Verified == 0 {
		t.Errorf("expected synthetic fixture to record VERIFIED for BL-02, got %+v", covActive)
	}
}

// 6. Test BL-03: State Manipulation & Parameter Integrity
func TestCategoryBL03_StateManipulation(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-bl03",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/order/update", Parameters: []string{"price", "status", "role"}},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov := summary.CategoryCoverageMap[string(CategoryStateManipulation)]
	if cov.Verified == 0 {
		t.Errorf("expected synthetic fixture state manipulation to record VERIFIED, got %+v", cov)
	}
}

// 7. Test BL-04: Unauthorized Workflow Access
func TestCategoryBL04_UnauthorizedWorkflowAccess(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-bl04",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/admin/approve_step", Type: "approve"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov := summary.CategoryCoverageMap[string(CategoryUnauthorizedWorkflowAccess)]
	if cov.Verified == 0 {
		t.Errorf("expected synthetic fixture unauthorized workflow to record VERIFIED for BL-04, got %+v", cov)
	}
}

// 8. Test BL-05: Sensitive Business-Flow Abuse
func TestCategoryBL05_SensitiveFlowAbuse(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-bl05",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/coupon/redeem", Type: "redeem"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov := summary.CategoryCoverageMap[string(CategorySensitiveFlowAbuse)]
	if cov.Verified == 0 {
		t.Errorf("expected synthetic fixture flow abuse to record VERIFIED for BL-05, got %+v", cov)
	}
}

// 9. Test BL-06: Replay & Idempotency Flaws
func TestCategoryBL06_ReplayAndIdempotency(t *testing.T) {
	// Scenario A: Safety gating blocks replay when AllowStateChanging is false
	cfgSafe := DefaultConfig()
	cfgSafe.AllowStateChanging = false
	engineSafe := NewEngine(nil, cfgSafe)

	actxSafe := &AssessmentContext{
		AssessmentID: "asm-bl06-safe",
		BaseURL:      "http://127.0.0.1:18080",
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/account/transfer", Type: "transfer"},
		},
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

	// Scenario B: Synthetic fixture replay flaw verification
	engineActive := NewEngine(nil, DefaultConfig())
	actxActive := &AssessmentContext{
		AssessmentID:     "asm-bl06-active",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/account/transfer", Type: "transfer"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summaryActive, err := engineActive.Assess(context.Background(), actxActive)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	covActive := summaryActive.CategoryCoverageMap[string(CategoryReplayIdempotency)]
	if covActive.Verified == 0 {
		t.Errorf("expected synthetic fixture to record VERIFIED for BL-06, got %+v", covActive)
	}
}

// 10. Test BL-07: Privilege & State Inconsistency
func TestCategoryBL07_PrivilegeStateInconsistency(t *testing.T) {
	// Missing identities in live mode -> INCONCLUSIVE
	engine := NewEngine(nil, DefaultConfig())
	actxNoIdentities := &AssessmentContext{
		AssessmentID: "asm-bl07-none",
		BaseURL:      "http://127.0.0.1:18080",
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/workflow/step2"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summaryNone, err := engine.Assess(context.Background(), actxNoIdentities)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	covNone := summaryNone.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
	if covNone.Inconclusive == 0 {
		t.Errorf("expected missing identities to record Inconclusive for BL-07, got %+v", covNone)
	}

	// Synthetic fixture verification
	actxPriv := &AssessmentContext{
		AssessmentID:     "asm-bl07-priv",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Identities: []TestIdentity{
			{ID: "user-a", Role: "buyer", PrivilegeLevel: 1},
			{ID: "user-b", Role: "admin", PrivilegeLevel: 5},
		},
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/workflow/step2"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summaryPriv, err := engine.Assess(context.Background(), actxPriv)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	covPriv := summaryPriv.CategoryCoverageMap[string(CategoryPrivilegeStateMismatch)]
	if covPriv.Verified == 0 {
		t.Errorf("expected synthetic fixture to record VERIFIED for BL-07, got %+v", covPriv)
	}
}

// 11. Test BL-08: Business Data Validation & Invariants
func TestCategoryBL08_BusinessDataValidation(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-bl08",
		BaseURL:          "http://127.0.0.1:18080",
		SyntheticFixture: true,
		Endpoints: []DiscoveredEndpoint{
			{Method: "POST", Path: "/cart/checkout", Parameters: []string{"quantity", "price", "discount"}},
		},
		IsAllowed: func(u string) bool { return true },
	}

	_, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov := summary.CategoryCoverageMap[string(CategoryDataValidationInvariants)]
	if cov.Verified == 0 {
		t.Errorf("expected synthetic fixture to record VERIFIED for BL-08, got %+v", cov)
	}
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
