package bola

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
)

func newApprovedAuthzRecord() *auth.AuthorizationRecord {
	from := time.Now().Add(-1 * time.Hour)
	until := time.Now().Add(24 * time.Hour)
	return &auth.AuthorizationRecord{
		ID:                  "phase4-bola-authz",
		AuthorizingParty:    "Phase4 Test Operator",
		AuthorizationMethod: "EXPLICIT_TEST_CERTIFICATION",
		Status:              "APPROVED",
		ValidFrom:           &from,
		ValidUntil:          &until,
	}
}

func TestPhase4BOLA_DynamicDiscovery_PathsQueryJSONOpenAPI(t *testing.T) {
	openAPI := `{
		"openapi": "3.0.0",
		"paths": {
			"/api/v1/orders/{order_id}": {
				"get": {"summary": "Get order by ID"}
			},
			"/api/v1/health": {
				"get": {"summary": "Health check"}
			}
		}
	}`

	observations := []DiscoveryObservation{
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/openapi.json",
			Path:            "/openapi.json",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(openAPI),
			DiscoveryMethod: "OPENAPI_SPEC",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/api/me",
			Path:            "/api/me",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"id":"usr_alice","username":"alice","email":"alice@example.test"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_B",
			URL:             "http://127.0.0.1:8080/api/me",
			Path:            "/api/me",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"id":"usr_bob","username":"bob","email":"bob@example.test"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/api/v1/orders/1001",
			Path:            "/api/v1/orders/1001",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"order_id":"1001","owner_id":"usr_alice","private_note":"alice secret shipment"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/api/v1/invoices?invoice_id=inv_42",
			Path:            "/api/v1/invoices",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"invoice_id":"inv_42","username":"alice","balance":"920.00"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
			QueryParams:     []string{"invoice_id"},
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/api/v1/health",
			Path:            "/api/v1/health",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"status":"ok"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/static/app.js",
			Path:            "/static/app.js",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/javascript",
			Body:            []byte(`console.log("static");`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "STATIC_ASSET",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:8080/api/v1/orders/1001/delete",
			Path:            "/api/v1/orders/1001/delete",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"deleted":true}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
	}

	identities := []TestIdentity{
		{Alias: "USER_A", Role: "user", Username: "alice"},
		{Alias: "USER_B", Role: "user", Username: "bob"},
	}

	surface := DiscoverObjectSurface("http://127.0.0.1:8080", identities, observations, 30)
	if len(surface.Objects) < 2 {
		t.Fatalf("expected >= 2 owned objects dynamically discovered, got %d (%+v)", len(surface.Objects), surface.Objects)
	}

	foundOrder := false
	foundInvoice := false
	for _, obj := range surface.Objects {
		if obj.ID == "1001" {
			foundOrder = true
			if !strings.EqualFold(obj.OwnerIdentity, "USER_A") || !obj.OwnershipEstablished {
				t.Fatalf("expected order 1001 owned and established for USER_A, got %+v", obj)
			}
		}
		if obj.ID == "inv_42" && obj.Location == "query" {
			foundInvoice = true
			if !strings.EqualFold(obj.OwnerIdentity, "USER_A") {
				t.Fatalf("expected invoice inv_42 owned by USER_A, got %+v", obj)
			}
		}
		if obj.ID == "v1" || obj.ID == "health" || strings.Contains(obj.TemplatePath, "static") || strings.Contains(obj.TemplatePath, "delete") {
			t.Fatalf("unexpected non-object/version/static/destructive object discovered: %+v", obj)
		}
	}
	if !foundOrder || !foundInvoice {
		t.Fatalf("expected both path order (1001) and query invoice (inv_42), foundOrder=%v foundInvoice=%v", foundOrder, foundInvoice)
	}
}

func TestPhase4BOLA_UnconfirmedOwnership_IsolatedCookiesAndNeverFalseVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieHeader := r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/shared-docs/doc_99":
			// Requires some session cookie, returns identical non-owned doc
			if cookieHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"login required"}`))
				return
			}
			// Check there is zero cross-identity cookie bleed
			if strings.Contains(cookieHeader, "sid_alice") && strings.Contains(cookieHeader, "sid_bob") {
				t.Errorf("cookie bleed detected in request header: %q", cookieHeader)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"doc_id":       "doc_99",
				"private_note": "shared-team-bulletin-doc99",
			})
		case "/api/orders/ord_alice_1":
			if strings.Contains(cookieHeader, "sid_bob") || strings.Contains(cookieHeader, "sid_alice") {
				// Vulnerable BOLA with isolated cookie jars
				_ = json.NewEncoder(w).Encode(map[string]any{
					"order_id":     "ord_alice_1",
					"owner":        "alice",
					"private_note": "alice-secret-order-payload-1",
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	mgr, err := auth.NewIdentityManager(auth.IdentityManagerOptions{
		TargetURL:     srv.URL,
		ScopeAllowed:  func(string) bool { return true },
		AllowLoopback: true,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	if err := mgr.SetCookie(auth.IdentityUserA, auth.RoleVictim, "session=sid_alice_supersecret"); err != nil {
		t.Fatalf("SetCookie A: %v", err)
	}
	if err := mgr.SetCookie(auth.IdentityUserB, auth.RoleAttacker, "session=sid_bob_supersecret"); err != nil {
		t.Fatalf("SetCookie B: %v", err)
	}

	engine := NewEngine(mgr.BuildClient(auth.IdentityUserA), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-phase4-bola",
		ExecutionID:  "exec-phase4-bola",
		BaseURL:      srv.URL,
		Authorization: newApprovedAuthzRecord(),
		IsAllowed:     func(string) bool { return true },
		TestAllIdentities: true,
		Identities: []TestIdentity{
			{Alias: "USER_A", Role: "user", Username: "alice", Cookies: map[string]string{"session": "sid_alice_supersecret"}},
			{Alias: "USER_B", Role: "user", Username: "bob", Cookies: map[string]string{"session": "sid_bob_supersecret"}},
		},
		IdentityClients: map[string]*http.Client{
			"USER_A": mgr.ClientFor(auth.IdentityUserA),
			"USER_B": mgr.ClientFor(auth.IdentityUserB),
		},
		Endpoints: []EndpointTemplate{
			{Method: "GET", PathPattern: "/api/shared-docs/{doc_id}", Params: []string{"doc_id"}},
			{Method: "GET", PathPattern: "/api/orders/{order_id}", Params: []string{"order_id"}},
		},
		Objects: []ObjectIdentifier{
			{
				ID:                   "doc_99",
				Location:             "path",
				ParamName:            "doc_id",
				TemplatePath:         "/api/shared-docs/{doc_id}",
				OwnerIdentity:        "USER_A",
				OwnershipUnconfirmed: true,
				ProtectedData:        "shared-team-bulletin-doc99",
			},
			{
				ID:                   "ord_alice_1",
				Location:             "path",
				ParamName:            "order_id",
				TemplatePath:         "/api/orders/{order_id}",
				OwnerIdentity:        "USER_A",
				OwnershipEstablished: true,
				ProtectedData:        "alice-secret-order-payload-1",
			},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("engine.Assess failed: %v", err)
	}
	if summary.VerifiedCount != 1 {
		t.Fatalf("expected exactly 1 verified BOLA (ord_alice_1) and 0 false verified for unconfirmed doc_99, got verified=%d results=%+v", summary.VerifiedCount, results)
	}
	for _, r := range results {
		if r.ObjectID == "doc_99" && r.VerificationState == StateVerified {
			t.Fatalf("unconfirmed ownership doc_99 was falsely confirmed as StateVerified")
		}
		if r.Finding != nil {
			raw := r.Finding.Evidence + r.Finding.Description
			if strings.Contains(raw, "sid_alice_supersecret") || strings.Contains(raw, "sid_bob_supersecret") {
				t.Fatalf("secret cookie leaked in BOLA finding: %s", raw)
			}
		}
	}
}

func TestPhase4BOLA_StateChangingRequiresVerifiedFixture(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.AllowStateChangingTests = true
	engine := NewEngine(srv.Client(), cfg)

	actx := &AssessmentContext{
		AssessmentID:            "asm-bola-fixture-guard",
		ExecutionID:             "exec-bola-fixture-guard",
		BaseURL:                 srv.URL,
		Authorization:           newApprovedAuthzRecord(),
		IsAllowed:               func(string) bool { return true },
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		IsFixtureTarget:         func(string) bool { return false }, // denied by verifier
		Identities: []TestIdentity{
			{Alias: "USER_A", Role: "user", Headers: map[string]string{"Authorization": "Bearer tok_a"}},
			{Alias: "USER_B", Role: "user", Headers: map[string]string{"Authorization": "Bearer tok_b"}},
		},
		Endpoints: []EndpointTemplate{
			{Method: "PUT", PathPattern: "/api/orders/{order_id}", IsStateChanging: true},
		},
		Objects: []ObjectIdentifier{
			{ID: "101", OwnerIdentity: "USER_A", OwnershipEstablished: true, TemplatePath: "/api/orders/{order_id}"},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess error: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected 0 write hits when fixture verifier returns false, got %d", hits)
	}
	if len(results) != 1 || results[0].VerificationState != StateSkipped || summary.SkippedCount != 1 {
		t.Fatalf("expected single StateSkipped result, got results=%+v summary=%+v", results, summary)
	}
}
