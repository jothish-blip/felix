package bfla

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
		ID:                  "phase4-bfla-authz",
		AuthorizingParty:    "Phase4 Test Operator",
		AuthorizationMethod: "EXPLICIT_TEST_CERTIFICATION",
		Status:              "APPROVED",
		ValidFrom:           &from,
		ValidUntil:          &until,
	}
}

func TestPhase4BFLA_DestructiveExclusionClassifier(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{"DELETE", "/api/users/42", true},
		{"POST", "/api/admin/wipe", true},
		{"POST", "/api/account/password", true},
		{"POST", "/api/billing/payment", true},
		{"GET", "/api/admin/audit", false},
		{"GET", "/api/internal/metrics", false},
	}
	for _, tc := range cases {
		if got := IsDestructiveFunction(tc.method, tc.path); got != tc.want {
			t.Fatalf("IsDestructiveFunction(%q, %q) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestPhase4BFLA_DiscoveryAndAntiFalsePositiveEnforcement(t *testing.T) {
	var destructiveCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		isAdmin := authHdr == "Bearer admin-tok-phase4"
		isUser := authHdr == "Bearer user-tok-phase4"

		switch r.URL.Path {
		case "/api/admin/audit":
			// Vulnerable admin audit endpoint: leaked to regular users too
			if !isAdmin && !isUser {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"audit_events": []string{"role_grant:admin", "token_rotate"},
				"admin_report": true,
			})
		case "/api/admin/panel":
			// HTTP 200 login HTML trap for lower privilege
			if isAdmin {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"panel_secret": "admin-console-ok"})
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Sign In</h1><form action="/login"><input type="password"/></form></body></html>`))
		case "/api/admin/logs":
			// HTTP 200 JSON error trap
			if isAdmin {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"system_logs": []string{"boot ok"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"forbidden","authorized":false,"message":"access denied"}`))
		case "/api/internal/ping":
			// Name looks internal, actually open/public ping with identical response and no role evidence
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/api/admin/wipe":
			atomic.AddInt32(&destructiveCalls, 1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	openAPI := `{
		"openapi":"3.0.0",
		"paths":{
			"/api/admin/audit":{"get":{"x-roles":["admin"],"summary":"Admin audit feed"}},
			"/api/admin/panel":{"get":{"x-roles":["admin"],"summary":"Admin panel"}},
			"/api/admin/logs":{"get":{"x-roles":["admin"],"summary":"Admin logs"}},
			"/api/admin/wipe":{"post":{"x-roles":["admin"],"summary":"Wipe database"}}
		}
	}`

	observations := []DiscoveryObservation{
		{
			Identity:        "ADMIN",
			URL:             srv.URL + "/openapi.json",
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
			URL:             srv.URL + "/api/internal/ping",
			Path:            "/api/internal/ping",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"ok":true}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "ENDPOINT_CANDIDATE",
		},
	}

	identities := []TestIdentity{
		{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
		{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
		{Alias: "ANONYMOUS", Role: "anonymous", PrivilegeLevel: 0},
	}

	surface := DiscoverFunctionSurface(srv.URL, identities, observations, 30)
	if len(surface.Policies) < 4 {
		t.Fatalf("expected >=4 discovered policies, got %d", len(surface.Policies))
	}

	mgr, err := auth.NewIdentityManager(auth.IdentityManagerOptions{
		TargetURL:     srv.URL,
		ScopeAllowed:  func(string) bool { return true },
		AllowLoopback: true,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	mgr.SetBearerToken(auth.IdentityAdmin, auth.RoleAdmin, "admin-tok-phase4")
	mgr.SetBearerToken(auth.IdentityUserA, auth.RoleVictim, "user-tok-phase4")

	engine := NewEngine(mgr.BuildClient(auth.IdentityUserA), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:      "asm-phase4-bfla",
		ExecutionID:       "exec-phase4-bfla",
		BaseURL:           srv.URL,
		Policies:          surface.Policies,
		Identities:        identities,
		TestAllIdentities: true,
		IdentityClients: map[string]*http.Client{
			"ADMIN":     mgr.ClientFor(auth.IdentityAdmin),
			"USER_A":    mgr.ClientFor(auth.IdentityUserA),
			"ANONYMOUS": mgr.ClientFor(auth.IdentityUnauthenticated),
		},
		Authorization: newApprovedAuthzRecord(),
		IsAllowed:     func(string) bool { return true },
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("engine.Assess failed: %v", err)
	}
	if atomic.LoadInt32(&destructiveCalls) != 0 {
		t.Fatalf("expected zero destructive POST /api/admin/wipe calls, got %d", destructiveCalls)
	}
	if summary.VerifiedCount != 1 {
		t.Fatalf("expected exactly 1 verified BFLA (/api/admin/audit), got verified=%d results=%+v", summary.VerifiedCount, results)
	}
	for _, r := range results {
		switch r.Endpoint {
		case "/api/admin/panel", "/api/admin/logs", "/api/internal/ping":
			if r.VerificationState == StateVerified {
				t.Fatalf("trap/unestablished endpoint %s falsely verified: %+v", r.Endpoint, r)
			}
		case "/api/admin/audit":
			if strings.EqualFold(r.AccessorAlias, "USER_A") && r.VerificationState != StateVerified {
				t.Fatalf("expected USER_A on /api/admin/audit to be StateVerified, got %s", r.VerificationState)
			}
			if r.Finding != nil && (strings.Contains(r.Finding.Evidence, "admin-tok-phase4") || strings.Contains(r.Finding.Evidence, "user-tok-phase4")) {
				t.Fatalf("raw bearer token leaked in BFLA finding")
			}
		}
	}
}

func TestPhase4BFLA_StateChangingRequiresVerifiedFixture(t *testing.T) {
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
		AssessmentID:            "asm-bfla-fixture-guard",
		ExecutionID:             "exec-bfla-fixture-guard",
		BaseURL:                 srv.URL,
		Authorization:           newApprovedAuthzRecord(),
		IsAllowed:               func(string) bool { return true },
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		IsFixtureTarget:         func(string) bool { return false }, // denied by verifier
		Identities: []TestIdentity{
			{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5, Headers: map[string]string{"Authorization": "Bearer adm"}},
			{Alias: "USER_A", Role: "user", PrivilegeLevel: 1, Headers: map[string]string{"Authorization": "Bearer usr"}},
		},
		Policies: []FunctionPolicy{
			{
				FunctionID:             "admin-settings-post",
				Name:                   "Admin Settings Write",
				Category:               CategoryBFLAWriteMutation,
				Path:                   "/api/admin/settings",
				Method:                 "POST",
				IsStateChanging:        true,
				AllowedRoles:           []string{"admin"},
				RequiredPrivilegeLevel: 5,
			},
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
