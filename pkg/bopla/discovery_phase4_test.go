package bopla

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
)

func newApprovedAuthzRecord() *auth.AuthorizationRecord {
	from := time.Now().Add(-1 * time.Hour)
	until := time.Now().Add(24 * time.Hour)
	return &auth.AuthorizationRecord{
		ID:                  "phase4-bopla-authz",
		AuthorizingParty:    "Phase4 Test Operator",
		AuthorizationMethod: "EXPLICIT_TEST_CERTIFICATION",
		Status:              "APPROVED",
		ValidFrom:           &from,
		ValidUntil:          &until,
	}
}

func TestPhase4BOPLA_DestructivePropertyClassifier(t *testing.T) {
	if !IsDestructivePropertyAction("/api/account/password", "password") {
		t.Fatal("expected password endpoint to be classified destructive")
	}
	if !IsDestructivePropertyAction("/api/billing/subscription", "card_number") {
		t.Fatal("expected payment/billing property to be classified destructive")
	}
	if IsDestructivePropertyAction("/api/profile", "role") {
		t.Fatal("did not expect reversible /api/profile role property to be classified destructive")
	}
}

func TestPhase4BOPLA_DynamicDiscoveryAndReversibleMassAssignment(t *testing.T) {
	var mu sync.Mutex
	profileRole := "user"
	var writeCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		isAdmin := authHdr == "Bearer admin-tok-bopla"
		isUser := authHdr == "Bearer user-tok-bopla"
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/profile":
			if r.Method == http.MethodGet {
				mu.Lock()
				roleCopy := profileRole
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":           42,
					"display_name": "Alice",
					"role":         roleCopy,
				})
				return
			}
			if r.Method == http.MethodPut || r.Method == http.MethodPatch {
				atomic.AddInt32(&writeCalls, 1)
				if !isUser && !isAdmin {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				mu.Lock()
				if rVal, ok := payload["role"].(string); ok && rVal != "" {
					profileRole = rVal
				}
				roleCopy := profileRole
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":           42,
					"display_name": "Alice",
					"role":         roleCopy,
				})
				return
			}
		case "/api/preferences":
			// Echoed-only trap: echoes payload but NEVER persists on GET
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"plan_tier": "free",
				})
				return
			}
			if r.Method == http.MethodPatch || r.Method == http.MethodPut {
				atomic.AddInt32(&writeCalls, 1)
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				_ = json.NewEncoder(w).Encode(payload)
				return
			}
		case "/api/directory":
			// Excessive data exposure: exposes secret internal token/notes even to regular users,
			// while id and version are benign public fields
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":             7,
				"version":        "1.0",
				"internal_notes": "vip-backdoor-escalation-notes",
				"api_secret":     "sk_live_synthetic_1234567890",
			})
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	openAPI := `{
		"openapi":"3.0.0",
		"components":{"schemas":{
			"ProfileUpdate":{
				"type":"object",
				"properties":{
					"display_name":{"type":"string"},
					"role":{"type":"string","readOnly":true,"x-admin-only":true}
				}
			},
			"PrefUpdate":{
				"type":"object",
				"properties":{
					"plan_tier":{"type":"string","readOnly":true}
				}
			}
		}},
		"paths":{
			"/api/profile":{
				"get":{"summary":"Read profile"},
				"put":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ProfileUpdate"}}}}}
			},
			"/api/preferences":{
				"get":{"summary":"Read prefs"},
				"patch":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/PrefUpdate"}}}}}
			}
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
			URL:             srv.URL + "/api/directory",
			Path:            "/api/directory",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"id":7,"version":"1.0","internal_notes":"vip-backdoor-escalation-notes","api_secret":"sk_live_synthetic_1234567890"}`),
			DiscoveryMethod: "HTML_CRAWL",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             srv.URL + "/api/profile",
			Path:            "/api/profile",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"id":42,"display_name":"Alice","role":"user"}`),
			DiscoveryMethod: "HTML_FORM",
			Classification:  "OBSERVED_FORM",
			FormFieldNames:  []string{"display_name"},
		},
	}

	identities := []TestIdentity{
		{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
		{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
	}

	surface := DiscoverPropertySurface(srv.URL, identities, observations, 50)
	if len(surface.Policies) == 0 {
		t.Fatal("expected discovered BOPLA property policies")
	}
	for _, pol := range surface.Policies {
		if pol.PropertyPath == "id" || pol.PropertyPath == "version" {
			t.Fatalf("public benign property %q should not generate exposure policy", pol.PropertyPath)
		}
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
	mgr.SetBearerToken(auth.IdentityAdmin, auth.RoleAdmin, "admin-tok-bopla")
	mgr.SetBearerToken(auth.IdentityUserA, auth.RoleVictim, "user-tok-bopla")

	// Phase 1: Safe default (AllowStateChangingTests=false) must skip writes
	safeCfg := DefaultConfig()
	safeCfg.AllowActiveTesting = true
	safeCfg.AllowStateChangingTests = false
	safeEngine := NewEngine(mgr.BuildClient(auth.IdentityUserA), safeCfg)
	safeCtx := &AssessmentContext{
		AssessmentID:            "asm-phase4-bopla-safe",
		ExecutionID:             "exec-phase4-bopla-safe",
		BaseURL:                 srv.URL,
		Policies:                surface.Policies,
		Identities:              identities,
		TestAllIdentities:       true,
		AllowStateChangingTests: false,
		SyntheticFixture:        false,
		IdentityClients: map[string]*http.Client{
			"ADMIN":  mgr.ClientFor(auth.IdentityAdmin),
			"USER_A": mgr.ClientFor(auth.IdentityUserA),
		},
		Authorization: newApprovedAuthzRecord(),
		IsAllowed:     func(string) bool { return true },
	}
	_, safeSummary, err := safeEngine.Assess(context.Background(), safeCtx)
	if err != nil {
		t.Fatalf("safe BOPLA Assess failed: %v", err)
	}
	if safeSummary.SkippedCount == 0 || atomic.LoadInt32(&writeCalls) != 0 {
		t.Fatalf("expected writes skipped cleanly under default mode, skipped=%d writeCalls=%d", safeSummary.SkippedCount, atomic.LoadInt32(&writeCalls))
	}

	// Phase 2: Opted-in reversible Mass Assignment test must verify /api/profile role,
	// leave /api/preferences plan_tier NOT verified (echoed-only), and restore original state
	optCfg := DefaultConfig()
	optCfg.AllowActiveTesting = true
	optCfg.AllowStateChangingTests = true
	optEngine := NewEngine(mgr.BuildClient(auth.IdentityUserA), optCfg)
	optCtx := &AssessmentContext{
		AssessmentID:            "asm-phase4-bopla-opt",
		ExecutionID:             "exec-phase4-bopla-opt",
		BaseURL:                 srv.URL,
		Policies:                surface.Policies,
		Identities:              identities,
		TestAllIdentities:       true,
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		IdentityClients: map[string]*http.Client{
			"ADMIN":  mgr.ClientFor(auth.IdentityAdmin),
			"USER_A": mgr.ClientFor(auth.IdentityUserA),
		},
		Authorization: newApprovedAuthzRecord(),
		IsAllowed:     func(string) bool { return true },
	}
	optResults, _, err := optEngine.Assess(context.Background(), optCtx)
	if err != nil {
		t.Fatalf("opt-in BOPLA Assess failed: %v", err)
	}

	foundVerifiedProfileRole := false
	for _, r := range optResults {
		if r.Endpoint == "/api/profile" && r.PropertyPath == "role" && r.VerificationState == StateVerified {
			foundVerifiedProfileRole = true
		}
		if r.Endpoint == "/api/preferences" && r.PropertyPath == "plan_tier" && r.VerificationState == StateVerified {
			t.Fatalf("echoed-only /api/preferences plan_tier must never reach StateVerified, got %+v", r)
		}
	}
	if !foundVerifiedProfileRole {
		t.Fatalf("expected persisted mass-assignment StateVerified on /api/profile.role, results=%+v", optResults)
	}

	mu.Lock()
	restoredRole := profileRole
	mu.Unlock()
	if restoredRole != "user" {
		t.Fatalf("expected reversible mass assignment cleanup to restore profile role to \"user\", got %q", restoredRole)
	}
}

func TestPhase4BOPLA_SyntheticFixtureVerification_Hardened(t *testing.T) {
	if IsIsolatedFixtureTarget("http://payments.corp.internal/api/profile", nil, nil) {
		t.Fatal("expected internal corporate domain .internal to be rejected as an unverified fixture target")
	}
	if IsIsolatedFixtureTarget("http://app.local/api/profile", nil, nil) {
		t.Fatal("expected generic .local domain to be rejected as an unverified fixture target")
	}
	if IsIsolatedFixtureTarget("https://prod.example.com/api/profile", []string{"127.0.0.1:8080"}, nil) {
		t.Fatal("expected non-matching host to be rejected when explicit fixture list is set")
	}
	if !IsIsolatedFixtureTarget("http://127.0.0.1:8080/api/profile", []string{"127.0.0.1:8080"}, nil) {
		t.Fatal("expected matching pinned host:port to pass fixture target check")
	}
	if IsIsolatedFixtureTarget("http://127.0.0.1:9090/api/profile", []string{"127.0.0.1:8080"}, nil) {
		t.Fatal("expected mismatched loopback port to be rejected when explicit host:port is pinned")
	}
	// Delegate verifier func must override default loopback convenience
	if IsIsolatedFixtureTarget("http://127.0.0.1:8080/api/profile", nil, func(string) bool { return false }) {
		t.Fatal("expected explicit IsFixtureTarget callback denial to block loopback target")
	}
}

func TestPhase4BOPLA_MassAssignment_CleanupFailureHandling(t *testing.T) {
	cases := []struct {
		name           string
		mode           string // "http500", "silent200", "readback503", "transport_err"
		expectedStatus string
		expectedSubstr string
	}{
		{
			name:           "Restore_HTTP_500",
			mode:           "http500",
			expectedStatus: "CLEANUP_FAILED",
			expectedSubstr: "non-2xx HTTP 500",
		},
		{
			name:           "Restore_Silent_200_NoOp",
			mode:           "silent200",
			expectedStatus: "CLEANUP_FAILED",
			expectedSubstr: "post-restore read-back still observed injected value",
		},
		{
			name:           "PostRestore_ReadBack_HTTP_503",
			mode:           "readback503",
			expectedStatus: "CLEANUP_UNVERIFIED",
			expectedSubstr: "post-restore verification read-back returned HTTP 503",
		},
		{
			name:           "Restore_Transport_Error",
			mode:           "transport_err",
			expectedStatus: "CLEANUP_FAILED",
			expectedSubstr: "restore request error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			roleVal := "user"
			restoreAttempted := false
			postRestoreReadCount := 0

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/profile" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				switch r.Method {
				case http.MethodGet:
					mu.Lock()
					restoredAlready := restoreAttempted
					cur := roleVal
					if restoredAlready {
						postRestoreReadCount++
					}
					mu.Unlock()
					if restoredAlready && tc.mode == "readback503" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte(`{"error":"readback unavailable"}`))
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"role": cur})
				case http.MethodPut:
					var payload map[string]any
					_ = json.NewDecoder(r.Body).Decode(&payload)
					requestedRole, _ := payload["role"].(string)
					if requestedRole == "user" {
						mu.Lock()
						restoreAttempted = true
						mu.Unlock()
						switch tc.mode {
						case "http500":
							w.WriteHeader(http.StatusInternalServerError)
							_, _ = w.Write([]byte(`{"error":"restore failed"}`))
							return
						case "silent200":
							// Pretend restore succeeded without reverting roleVal
							w.Header().Set("Content-Type", "application/json")
							_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
							return
						case "transport_err":
							if hj, ok := w.(http.Hijacker); ok {
								if conn, _, err := hj.Hijack(); err == nil {
									_ = conn.Close()
									return
								}
							}
							w.WriteHeader(http.StatusBadGateway)
							return
						case "readback503":
							mu.Lock()
							roleVal = "user"
							mu.Unlock()
							w.Header().Set("Content-Type", "application/json")
							_ = json.NewEncoder(w).Encode(map[string]any{"role": "user"})
							return
						}
					}
					mu.Lock()
					if requestedRole != "" {
						roleVal = requestedRole
					}
					cur := roleVal
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"role": cur})
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
			mgr.SetBearerToken(auth.IdentityAdmin, auth.RoleAdmin, "admin-tok-cleanup")
			mgr.SetBearerToken(auth.IdentityUserA, auth.RoleVictim, "user-tok-cleanup")

			cfg := DefaultConfig()
			cfg.AllowActiveTesting = true
			cfg.AllowStateChangingTests = true
			engine := NewEngine(mgr.BuildClient(auth.IdentityUserA), cfg)

			actx := &AssessmentContext{
				AssessmentID:            "asm-cleanup-test",
				ExecutionID:             "exec-cleanup-test",
				BaseURL:                 srv.URL,
				AllowStateChangingTests: true,
				SyntheticFixture:        true,
				TestAllIdentities:       true,
				Identities: []TestIdentity{
					{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
					{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
				},
				IdentityClients: map[string]*http.Client{
					"ADMIN":  mgr.ClientFor(auth.IdentityAdmin),
					"USER_A": mgr.ClientFor(auth.IdentityUserA),
				},
				Policies: []PropertyPolicy{
					{
						PropertyID:       "profile-role-write",
						Name:             "Mass Assignment on role",
						Category:         CategoryBOPLAMassAssignment,
						Endpoint:         "/api/profile",
						Method:           "PUT",
						ReadBackEndpoint: "/api/profile",
						ReadBackMethod:   "GET",
						PropertyPath:     "role",
						ExpectedAccess:   ExpectedAuthorizedOnly,
						AllowedRoles:     []string{"admin"},
						IsStateChanging:  true,
						IsReversibleTest: true,
						MutationValue:    "admin",
						MutationPayload:  `{"role":"admin"}`,
						RestorePayload:   `{"role":"user"}`,
						PolicyEvidence:   "Explicit admin-only property policy for test",
					},
				},
				Authorization: newApprovedAuthzRecord(),
				IsAllowed:     func(string) bool { return true },
			}

			results, summary, err := engine.Assess(context.Background(), actx)
			if err != nil {
				t.Fatalf("Assess unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 BOPLA result, got %d", len(results))
			}
			res := results[0]
			if res.VerificationState != StateVerified {
				t.Fatalf("expected underlying BOPLA mass assignment to remain StateVerified, got %s (%s)", res.VerificationState, res.EvidenceSummary)
			}
			if res.CleanupStatus != tc.expectedStatus {
				t.Fatalf("expected CleanupStatus=%s, got %q (warning=%q)", tc.expectedStatus, res.CleanupStatus, res.CleanupWarning)
			}
			if !strings.Contains(res.CleanupWarning, tc.expectedSubstr) {
				t.Fatalf("expected CleanupWarning to contain %q, got %q", tc.expectedSubstr, res.CleanupWarning)
			}
			if res.Finding == nil {
				t.Fatal("expected populated Finding for verified BOPLA violation")
			}
			if res.Finding.EvidenceDetails.Details["cleanup_status"] != tc.expectedStatus {
				t.Fatalf("expected finding details cleanup_status=%s, got %q", tc.expectedStatus, res.Finding.EvidenceDetails.Details["cleanup_status"])
			}
			if !strings.Contains(res.Finding.Evidence, "CLEANUP WARNING") || !strings.Contains(res.Finding.Remediation, tc.expectedStatus) {
				t.Fatalf("expected finding Evidence and Remediation to surface cleanup failure warning")
			}
			if summary == nil || summary.CleanupAttempted != 1 {
				t.Fatalf("expected summary CleanupAttempted=1, got %+v", summary)
			}
			if tc.expectedStatus == "CLEANUP_FAILED" && summary.CleanupFailed != 1 {
				t.Fatalf("expected summary CleanupFailed=1, got %+v", summary)
			}
			if tc.expectedStatus == "CLEANUP_UNVERIFIED" && summary.CleanupUnverified != 1 {
				t.Fatalf("expected summary CleanupUnverified=1, got %+v", summary)
			}
		})
	}
}

func TestPhase4BOPLA_MassAssignment_CleanupFailureStopsSubsequentMutations(t *testing.T) {
	var mu sync.Mutex
	roleVal := "user"
	var profilePutHits int32
	var settingsPutHits int32
	var directoryGetHits int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/profile":
			switch r.Method {
			case http.MethodGet:
				mu.Lock()
				cur := roleVal
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"role": cur})
			case http.MethodPut:
				atomic.AddInt32(&profilePutHits, 1)
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				if requested, _ := payload["role"].(string); requested == "user" {
					// Restoration fails with HTTP 500
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"restore failed"}`))
					return
				} else if requested != "" {
					mu.Lock()
					roleVal = requested
					mu.Unlock()
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"role": roleVal})
			}
		case "/api/settings":
			atomic.AddInt32(&settingsPutHits, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tier":"enterprise"}`))
		case "/api/directory":
			atomic.AddInt32(&directoryGetHits, 1)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.Header.Get("Authorization"), "admin-tok") {
				_, _ = w.Write([]byte(`{"internal_notes":"vip-secret"}`))
			} else {
				_, _ = w.Write([]byte(`{"internal_notes":"vip-secret"}`))
			}
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
	mgr.SetBearerToken(auth.IdentityAdmin, auth.RoleAdmin, "admin-tok")
	mgr.SetBearerToken(auth.IdentityUserA, auth.RoleVictim, "user-a-tok")
	mgr.SetBearerToken(auth.IdentityUserB, auth.RoleAttacker, "user-b-tok")

	cfg := DefaultConfig()
	cfg.AllowActiveTesting = true
	cfg.AllowStateChangingTests = true
	engine := NewEngine(mgr.BuildClient(auth.IdentityUserA), cfg)

	actx := &AssessmentContext{
		AssessmentID:            "asm-cleanup-halt",
		ExecutionID:             "exec-cleanup-halt",
		BaseURL:                 srv.URL,
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		TestAllIdentities:       true,
		Identities: []TestIdentity{
			{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
			{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
			{Alias: "USER_B", Role: "user", PrivilegeLevel: 1},
		},
		IdentityClients: map[string]*http.Client{
			"ADMIN":  mgr.ClientFor(auth.IdentityAdmin),
			"USER_A": mgr.ClientFor(auth.IdentityUserA),
			"USER_B": mgr.ClientFor(auth.IdentityUserB),
		},
		Policies: []PropertyPolicy{
			{
				PropertyID:       "profile-role-write",
				Name:             "Mass Assignment on role",
				Category:         CategoryBOPLAMassAssignment,
				Endpoint:         "/api/profile",
				Method:           "PUT",
				ReadBackEndpoint: "/api/profile",
				ReadBackMethod:   "GET",
				PropertyPath:     "role",
				ExpectedAccess:   ExpectedAuthorizedOnly,
				AllowedRoles:     []string{"admin"},
				IsStateChanging:  true,
				IsReversibleTest: true,
				MutationValue:    "admin",
				MutationPayload:  `{"role":"admin"}`,
				RestorePayload:   `{"role":"user"}`,
				PolicyEvidence:   "Explicit admin-only property policy for halt test",
			},
			{
				PropertyID:       "settings-tier-write",
				Name:             "Mass Assignment on tier",
				Category:         CategoryBOPLAMassAssignment,
				Endpoint:         "/api/settings",
				Method:           "PATCH",
				ReadBackEndpoint: "/api/settings",
				ReadBackMethod:   "GET",
				PropertyPath:     "tier",
				ExpectedAccess:   ExpectedAuthorizedOnly,
				AllowedRoles:     []string{"admin"},
				IsStateChanging:  true,
				IsReversibleTest: true,
				MutationValue:    "enterprise",
				MutationPayload:  `{"tier":"enterprise"}`,
				RestorePayload:   `{"tier":"free"}`,
				PolicyEvidence:   "Subsequent write policy that must be stopped after restore failure",
			},
			{
				PropertyID:      "dir-notes-read",
				Name:            "Excessive Exposure on internal_notes",
				Category:        CategoryBOPLAExcessiveExposure,
				Endpoint:        "/api/directory",
				Method:          "GET",
				PropertyPath:    "internal_notes",
				ExpectedAccess:  ExpectedAuthorizedOnly,
				AllowedRoles:    []string{"admin"},
				IsStateChanging: false,
				PolicyEvidence:  "Read-only exposure check should still continue safely after mutation halt",
			},
		},
		Authorization: newApprovedAuthzRecord(),
		IsAllowed:     func(string) bool { return true },
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&profilePutHits); got != 2 {
		t.Fatalf("expected exactly 2 PUTs on /api/profile (1 USER_A mutation + 1 failed restore), got %d", got)
	}
	if got := atomic.LoadInt32(&settingsPutHits); got != 0 {
		t.Fatalf("expected 0 mutation requests on subsequent /api/settings after restore failure, got %d", got)
	}
	if got := atomic.LoadInt32(&directoryGetHits); got == 0 {
		t.Fatalf("expected read-only /api/directory checks to still execute safely after write halt")
	}
	if summary == nil || summary.CleanupFailed != 1 || summary.SkippedCount != 2 || summary.ModificationTests != 1 {
		t.Fatalf("unexpected summary counts after cleanup halt: %+v", summary)
	}

	var userBSkipped, settingsSkipped, readVerified bool
	for _, r := range results {
		if r.Endpoint == "/api/profile" && r.AccessorAlias == "USER_B" && r.VerificationState == StateSkipped && strings.Contains(r.EvidenceSummary, "prior restoration failure") {
			userBSkipped = true
		}
		if r.Endpoint == "/api/settings" && r.VerificationState == StateSkipped && strings.Contains(r.EvidenceSummary, "prior restoration failure") {
			settingsSkipped = true
		}
		if r.Endpoint == "/api/directory" && r.VerificationState == StateVerified {
			readVerified = true
		}
	}
	if !userBSkipped || !settingsSkipped || !readVerified {
		t.Fatalf("expected USER_B & subsequent write skipped and read check still verified (userBSkipped=%v settingsSkipped=%v readVerified=%v)", userBSkipped, settingsSkipped, readVerified)
	}
}
