package bfla

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
)

func testApprovedAuth() *auth.AuthorizationRecord {
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	return &auth.AuthorizationRecord{
		ID:                  "auth-bfla-test",
		AuthorizingParty:    "Chief Information Security Officer",
		AuthorizationMethod: "Written",
		Status:              "APPROVED",
		ValidFrom:           &past,
		ValidUntil:          &future,
	}
}

// 1. Admin can execute admin function; non-admin receives 403 -> NOT_VULNERABLE
func TestBFLA_AdminCanExecuteAdminFunction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Authorization"), "token_admin") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","metrics":{"cpu":12,"memory":45}}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-metrics",
				Name:                    "Admin Metrics",
				Path:                    "/api/admin/metrics",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "metrics",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when non-admin receives 403, got %s", results[0].VerificationState)
	}
}

// 2. Lower privilege correctly denied access
func TestBFLA_LowerPrivilegeCorrectlyDenied_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_user") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"users":[{"id":1,"name":"alice"}]}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-users",
				Name:                    "Admin Users",
				Path:                    "/api/admin/users",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "users",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s", results[0].VerificationState)
	}
}

// 3. Lower privilege accesses admin function and receives protected data -> VERIFIED
func TestBFLA_LowerPrivilegeAdminAccess_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok","users":[{"id":101,"role":"admin"}],"sensitive_diagnostic":true}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-users",
				Name:                    "Admin Users Directory",
				Path:                    "/api/admin/users",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "users",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED when standard user accesses admin endpoint with protected marker, got %s", results[0].VerificationState)
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected summary VerifiedCount 1, got %d", summary.VerifiedCount)
	}
	if results[0].Finding == nil {
		t.Errorf("expected finding to be attached to VERIFIED result")
	}
}

// 4. Generic login page 200 OK -> No false positive (NOT_VULNERABLE)
func TestBFLA_GenericLoginPage200_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_user") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html><html><body><h1>Please Sign In</h1><form action="/login"><input type="password" name="pwd"/></form></body></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok","admin_data":"top_secret"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-portal",
				Name:                    "Admin Portal",
				Path:                    "/api/admin/portal",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "admin_data",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState == StateVerified {
		t.Errorf("false positive: HTML login form with HTTP 200 must NOT be marked VERIFIED")
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE for login challenge, got %s", results[0].VerificationState)
	}
}

// 5. Identical public response -> No false positive (INCONCLUSIVE)
func TestBFLA_IdenticalPublicResponse_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"service":"api","version":"1.2.3","status":"running"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-info",
				Name:                    "Admin Service Info",
				Path:                    "/api/admin/info",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState == StateVerified {
		t.Errorf("false positive: identical public response without privileged markers must NOT be VERIFIED")
	}
}

// 6. Generic error JSON 200 OK -> No false positive (NOT_VULNERABLE)
func TestBFLA_GenericErrorJSON_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Authorization"), "token_user") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"error":"forbidden","message":"Access denied: insufficient permissions for role user"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"admin_dashboard":"stats"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-dash",
				Name:                    "Admin Dashboard",
				Path:                    "/api/admin/dashboard",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "admin_dashboard",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE for application-level 200 error, got %s", results[0].VerificationState)
	}
}

// 7. Missing function policy / identity pairing -> INCONCLUSIVE
func TestBFLA_MissingFunctionPolicy_Inconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-orphan",
				Name:                    "Orphan Admin Function",
				Path:                    "/api/admin/orphan",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"superadmin"}, // no identity matches superadmin
				RestrictedRoles:         []string{"user"},
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "operator", Role: "operator", Headers: map[string]string{"Authorization": "Bearer token_op"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when allowed role identity is missing, got %s", results[0].VerificationState)
	}
}

// 8. Positive control failed -> INCONCLUSIVE
func TestBFLA_PositiveControlFailed_Inconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"database failure"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-metrics",
				Name:                    "Admin Metrics",
				Path:                    "/api/admin/metrics",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "metrics",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "std_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when positive control fails, got %s", results[0].VerificationState)
	}
}

// 9. Privilege Escalation -> VERIFIED
func TestBFLA_PrivilegeEscalation_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"config":{"master_key":"secret123","cluster":"prod"}}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "sys-config",
				Name:                    "System Configuration Access",
				Path:                    "/api/admin/config",
				Method:                  "GET",
				Category:                CategoryBFLAPrivilegeEscalation,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"operator"},
				RequiredPrivilegeLevel:  5,
				ProtectedResponseMarker: "master_key",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", PrivilegeLevel: 5, Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "operator_user", Role: "operator", PrivilegeLevel: 2, Headers: map[string]string{"Authorization": "Bearer token_operator"}},
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
		t.Errorf("expected VERIFIED for privilege escalation, got %s", results[0].VerificationState)
	}
	if results[0].Category != CategoryBFLAPrivilegeEscalation {
		t.Errorf("expected category BFLA-PRIVILEGE-ESCALATION, got %s", results[0].Category)
	}
}

// 10. Privilege Escalation -> Correctly Enforced (NOT_VULNERABLE)
func TestBFLA_PrivilegeEscalation_CorrectlyEnforced(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_operator") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"privilege level insufficient"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"master_key":"secret123"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "sys-config",
				Name:                    "System Configuration Access",
				Path:                    "/api/admin/config",
				Method:                  "GET",
				Category:                CategoryBFLAPrivilegeEscalation,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"operator"},
				RequiredPrivilegeLevel:  5,
				ProtectedResponseMarker: "master_key",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", PrivilegeLevel: 5, Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "operator_user", Role: "operator", PrivilegeLevel: 2, Headers: map[string]string{"Authorization": "Bearer token_operator"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s", results[0].VerificationState)
	}
}

// 11. Method Bypass -> VERIFIED
func TestBFLA_MethodBypass_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"settings":{"maintenance_mode":true}}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "settings-method",
				Name:                    "Settings Method Parity",
				Path:                    "/api/admin/settings",
				Method:                  "POST",
				Category:                CategoryBFLAMethodBypass,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "maintenance_mode",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user_alias", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
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
		t.Errorf("expected VERIFIED for method bypass, got %s", results[0].VerificationState)
	}
	if results[0].Category != CategoryBFLAMethodBypass {
		t.Errorf("expected CategoryBFLAMethodBypass, got %s", results[0].Category)
	}
}

// 12. Method Bypass -> Consistently Enforced (NOT_VULNERABLE)
func TestBFLA_MethodBypass_ConsistentlyEnforced(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_user") {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"maintenance_mode":true}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "settings-method",
				Name:                    "Settings Method Parity",
				Path:                    "/api/admin/settings",
				Method:                  "POST",
				Category:                CategoryBFLAMethodBypass,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "maintenance_mode",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user_alias", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive && results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE or INCONCLUSIVE for 405 Method Not Allowed, got %s", results[0].VerificationState)
	}
}

// 13. State changing requires explicit opt-in -> SKIPPED
func TestBFLA_WriteMutation_RequiresExplicitOptIn(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-01",
		ExecutionID:             "exec-01",
		BaseURL:                 ts.URL,
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: false, // write tests forbidden by default
		Policies: []FunctionPolicy{
			{
				FunctionID:      "delete-account",
				Name:            "Delete Account Function",
				Path:            "/api/admin/users/123",
				Method:          "DELETE",
				Category:        CategoryBFLAWriteMutation,
				AllowedRoles:    []string{"admin"},
				RestrictedRoles: []string{"user"},
				IsStateChanging: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED when AllowStateChangingTests is false, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("security violation: dispatched %d network requests for un-opted state-changing test", atomic.LoadInt32(&requestCount))
	}
}

// 14. Write mutation with opt-in and synthetic fixture -> VERIFIED
func TestBFLA_WriteMutation_OptIn_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"purged","records_deleted":42}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-01",
		ExecutionID:             "exec-01",
		BaseURL:                 ts.URL,
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-purge",
				Name:                    "Admin Purge",
				Path:                    "/api/admin/purge",
				Method:                  "POST",
				Category:                CategoryBFLAWriteMutation,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "purged",
				PositiveControlRequired: true,
				IsStateChanging:         true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
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
		t.Errorf("expected VERIFIED for opted-in write mutation, got %s", results[0].VerificationState)
	}
}

// 15. Identical identities -> INCONCLUSIVE
func TestBFLA_IdenticalIdentities_Inconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:      "admin-metrics",
				Name:            "Admin Metrics",
				Path:            "/api/admin/metrics",
				Method:          "GET",
				Category:        CategoryBFLAAdminEndpoint,
				AllowedRoles:    []string{"admin"},
				RestrictedRoles: []string{"user"},
			},
		},
		Identities: []TestIdentity{
			{Alias: "same_user", Role: "admin", Headers: map[string]string{"Authorization": "Bearer identical_token"}},
			{Alias: "same_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer identical_token"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when identities are identical, got %s", results[0].VerificationState)
	}
}

// 16. Missing or invalid authorization -> Zero requests dispatched
func TestBFLA_MissingAuthorization_ZeroRequests(t *testing.T) {
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())

	// Test nil authorization
	actxNil := &AssessmentContext{
		BaseURL:       ts.URL,
		Authorization: nil,
	}
	_, _, errNil := engine.Assess(context.Background(), actxNil)
	if errNil == nil {
		t.Fatalf("expected error when authorization is nil")
	}

	// Test unapproved authorization
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	actxUnapproved := &AssessmentContext{
		BaseURL: ts.URL,
		Authorization: &auth.AuthorizationRecord{
			ID:                  "auth-unapproved",
			Status:              "PENDING",
			AuthorizingParty:    "Security Team",
			AuthorizationMethod: "Written",
			ValidFrom:           &past,
			ValidUntil:          &future,
		},
	}
	_, _, errUnapp := engine.Assess(context.Background(), actxUnapproved)
	if errUnapp == nil {
		t.Fatalf("expected error when authorization is unapproved")
	}

	// Test expired authorization
	longAgo := time.Now().UTC().Add(-48 * time.Hour)
	recentlyPast := time.Now().UTC().Add(-1 * time.Hour)
	actxExpired := &AssessmentContext{
		BaseURL: ts.URL,
		Authorization: &auth.AuthorizationRecord{
			ID:                  "auth-expired",
			Status:              "APPROVED",
			AuthorizingParty:    "Security Team",
			AuthorizationMethod: "Written",
			ValidFrom:           &longAgo,
			ValidUntil:          &recentlyPast,
		},
	}
	_, _, errExp := engine.Assess(context.Background(), actxExpired)
	if errExp == nil {
		t.Fatalf("expected error when authorization is expired")
	}

	if atomic.LoadInt32(&reqCount) != 0 {
		t.Fatalf("security violation: expected 0 requests with invalid authorization, got %d", atomic.LoadInt32(&reqCount))
	}
}

// 17. Scope and exclusions -> Excluded endpoints are blocked
func TestBFLA_ScopeAndExclusions_Blocked(t *testing.T) {
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		IsExcluded: func(target string) bool {
			return strings.Contains(target, "/api/admin/excluded")
		},
		Policies: []FunctionPolicy{
			{
				FunctionID:      "admin-excluded",
				Name:            "Excluded Admin Function",
				Path:            "/api/admin/excluded",
				Method:          "GET",
				Category:        CategoryBFLAAdminEndpoint,
				AllowedRoles:    []string{"admin"},
				RestrictedRoles: []string{"user"},
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED for excluded endpoint, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&reqCount) != 0 {
		t.Errorf("expected 0 requests for excluded endpoint, got %d", atomic.LoadInt32(&reqCount))
	}
}

// 18. Redirects -> No credential leak across origins
func TestBFLA_Redirects_NoCredentialLeakAcrossOrigins(t *testing.T) {
	var targetReceivedAuth string
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"external":true}`)
	}))
	defer externalServer.Close()

	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalServer.URL+"/redirected", http.StatusFound)
	}))
	defer primaryServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       primaryServer.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-redir",
				Name:                    "Admin Redirect",
				Path:                    "/api/admin/redirect",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				PositiveControlRequired: false,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer secret_admin_token"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer secret_user_token"}},
		},
	}

	_, _, _ = engine.Assess(context.Background(), actx)
	if targetReceivedAuth != "" {
		t.Errorf("security violation: sensitive Authorization header leaked across origin redirect: %q", targetReceivedAuth)
	}
}

// 19. Remote cleartext HTTP -> Sensitive credentials withheld
func TestBFLA_RemoteCleartextHTTP_SensitiveCredentialsWithheld(t *testing.T) {
	mockBase := &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "" {
				t.Errorf("sensitive Authorization header was NOT stripped on remote cleartext HTTP")
			}
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		},
	}

	transport := &credentialGuardedTransport{
		base: mockBase,
	}

	// Remote unencrypted HTTP (non-loopback)
	req, _ := http.NewRequest("GET", "http://example.com/api/admin/metrics", nil)
	req.Header.Set("Authorization", "Bearer top_secret_admin_token")

	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Loopback unencrypted HTTP -> allowed to preserve credentials
	var loopbackReceivedAuth string
	loopbackMock := &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			loopbackReceivedAuth = req.Header.Get("Authorization")
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		},
	}
	loopbackTransport := &credentialGuardedTransport{base: loopbackMock}
	loopbackReq, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/admin/metrics", nil)
	loopbackReq.Header.Set("Authorization", "Bearer loopback_auth_token")

	_, err = loopbackTransport.RoundTrip(loopbackReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loopbackReceivedAuth != "Bearer loopback_auth_token" {
		t.Errorf("expected credentials preserved for loopback, got: %q", loopbackReceivedAuth)
	}
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

// 20. Dry run -> Zero network requests dispatched
func TestBFLA_DryRun_ZeroNetworkRequests(t *testing.T) {
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		DryRun:        true,
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	plan, err := engine.Plan(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.TotalTests == 0 {
		t.Errorf("expected plan to have tests, got 0")
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error on dry-run assess: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results from dry run assess, got %d", len(results))
	}
	if atomic.LoadInt32(&reqCount) != 0 {
		t.Errorf("expected 0 requests on dry run, got %d", atomic.LoadInt32(&reqCount))
	}
}

// 21. Request budget -> Enforced concurrently
func TestBFLA_RequestBudget_EnforcedConcurrently(t *testing.T) {
	var processed int32
	mock := &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&processed, 1)
			time.Sleep(10 * time.Millisecond)
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		},
	}

	var count int32
	transport := &credentialGuardedTransport{
		base:        mock,
		maxRequests: 5,
		reqCount:    &count,
	}

	var wg sync.WaitGroup
	var errorCount int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://127.0.0.1/test", nil)
			_, err := transport.RoundTrip(req)
			if err != nil && strings.Contains(err.Error(), "request budget exceeded") {
				atomic.AddInt32(&errorCount, 1)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&processed) > 5 {
		t.Errorf("expected at most 5 requests processed, got %d", atomic.LoadInt32(&processed))
	}
	if atomic.LoadInt32(&errorCount) != 5 {
		t.Errorf("expected exactly 5 budget exceeded errors, got %d", atomic.LoadInt32(&errorCount))
	}
}

// 22. Cancellation and timeout
func TestBFLA_CancellationAndTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	_, _, err := engine.Assess(ctx, actx)
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
}

// 23. Oversized responses bounded safely
func TestBFLA_OversizedResponses_Bounded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write 2MB of data
		padding := make([]byte, 2*1024*1024)
		w.Write(padding)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.MaxBodyReadBytes = 10 * 1024 // 10KB bounded limit
	engine := NewEngine(nil, cfg)

	respData, err := engine.executeRequest(context.Background(), engine.client, "GET", ts.URL, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int64(len(respData.Body)) > cfg.MaxBodyReadBytes {
		t.Errorf("expected response body bounded to %d bytes, got %d bytes", cfg.MaxBodyReadBytes, len(respData.Body))
	}
}

// 24. Secrets redacted in findings and evidence
func TestBFLA_SecretsRedactedInFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"secret_api_key":"super_confidential_token_12345","users":["alice"]}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-keys",
				Name:                    "Admin Keys",
				Path:                    "/api/admin/keys",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "users",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer super_secret_admin_token"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer super_secret_user_token"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Finding != nil {
		findingJSON, _ := json.Marshal(results[0].Finding)
		fStr := string(findingJSON)
		if strings.Contains(fStr, "super_secret_admin_token") || strings.Contains(fStr, "super_secret_user_token") {
			t.Errorf("secret bearer token was not redacted from finding: %s", fStr)
		}
	}
}

// 25. Findings deterministic across repeated runs
func TestBFLA_FindingsDeterministicAcrossRuns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok","users":[{"id":1}]}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	makeActx := func() *AssessmentContext {
		return &AssessmentContext{
			AssessmentID:  "asm-01",
			ExecutionID:   "exec-01",
			BaseURL:       ts.URL,
			Authorization: testApprovedAuth(),
			Policies: []FunctionPolicy{
				{
					FunctionID:              "admin-users",
					Name:                    "Admin Users",
					Path:                    "/api/admin/users",
					Method:                  "GET",
					Category:                CategoryBFLAAdminEndpoint,
					AllowedRoles:            []string{"admin"},
					RestrictedRoles:         []string{"user"},
					ProtectedResponseMarker: "users",
					PositiveControlRequired: true,
				},
			},
			Identities: []TestIdentity{
				{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_a"}},
				{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_b"}},
			},
		}
	}

	res1, sum1, err1 := engine.Assess(context.Background(), makeActx())
	res2, sum2, err2 := engine.Assess(context.Background(), makeActx())

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v / %v", err1, err2)
	}
	if len(res1) != len(res2) || res1[0].VerificationState != res2[0].VerificationState {
		t.Errorf("non-deterministic outcome: res1=%s, res2=%s", res1[0].VerificationState, res2[0].VerificationState)
	}
	if sum1.VerifiedCount != sum2.VerifiedCount {
		t.Errorf("summary counts differ across runs")
	}
}

// 26. Distinct tokens and cookies with zero cross-talk
func TestBFLA_DistinctTokensAndCookies_NoBleed(t *testing.T) {
	var adminHeader, userHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "admin") {
			adminHeader = authHdr
		} else if strings.Contains(authHdr, "user") {
			userHeader = authHdr
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"metrics":true}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-metrics",
				Name:                    "Admin Metrics",
				Path:                    "/api/admin/metrics",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "metrics",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer admin_unique_token"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer user_unique_token"}},
		},
	}

	_, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adminHeader != "Bearer admin_unique_token" {
		t.Errorf("expected adminHeader 'Bearer admin_unique_token', got %q", adminHeader)
	}
	if userHeader != "Bearer user_unique_token" {
		t.Errorf("expected userHeader 'Bearer user_unique_token', got %q", userHeader)
	}
}

// 27. Missing protected marker -> CANDIDATE
func TestBFLA_MissingProtectedMarker_Candidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.Header.Get("Authorization"), "token_admin") {
			fmt.Fprint(w, `{"status":"ok","secret_marker":"found"}`)
		} else {
			// Returns 200 OK but without secret_marker
			fmt.Fprint(w, `{"status":"ok","unrelated_data":"value"}`)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []FunctionPolicy{
			{
				FunctionID:              "admin-marker-test",
				Name:                    "Admin Marker Test",
				Path:                    "/api/admin/marker",
				Method:                  "GET",
				Category:                CategoryBFLAAdminEndpoint,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				ProtectedResponseMarker: "secret_marker",
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer token_admin"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer token_user"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateCandidate {
		t.Errorf("expected CANDIDATE when 200 is returned without protected marker, got %s", results[0].VerificationState)
	}
}

// 28. Policy file parsing and validation
func TestBFLA_PolicyFile_LoadingAndValidation(t *testing.T) {
	validJSON := `{
		"version": "1.0",
		"policies": [
			{
				"function_id": "pol-01",
				"name": "Admin Endpoint Policy",
				"path": "/api/admin/test",
				"method": "GET",
				"category": "BFLA-ADMIN-ENDPOINT",
				"allowed_roles": ["admin"],
				"restricted_roles": ["user"],
				"required_privilege_level": 5,
				"protected_response_marker": "admin_only"
			}
		],
		"identities": [
			{
				"alias": "admin_alias",
				"role": "admin",
				"privilege_level": 5
			}
		]
	}`

	var pf PolicyFile
	err := json.Unmarshal([]byte(validJSON), &pf)
	if err != nil {
		t.Fatalf("failed to unmarshal valid policy file: %v", err)
	}
	if len(pf.Policies) != 1 || pf.Policies[0].FunctionID != "pol-01" {
		t.Errorf("unexpected policy content: %+v", pf.Policies)
	}
	if len(pf.Identities) != 1 || pf.Identities[0].Alias != "admin_alias" {
		t.Errorf("unexpected identities content: %+v", pf.Identities)
	}
}

// 29. Multi-category summary and coverage aggregation
func TestBFLA_SummaryAndCoverageAggregation(t *testing.T) {
	results := []Result{
		{
			Category:          CategoryBFLAAdminEndpoint,
			VerificationState: StateVerified,
		},
		{
			Category:          CategoryBFLAAdminEndpoint,
			VerificationState: StateNotVulnerable,
		},
		{
			Category:          CategoryBFLAPrivilegeEscalation,
			VerificationState: StateCandidate,
		},
		{
			Category:          CategoryBFLAMethodBypass,
			VerificationState: StateInconclusive,
		},
		{
			Category:          CategoryBFLAWriteMutation,
			VerificationState: StateSkipped,
		},
	}

	summary := compileSummary(results)
	if summary.TotalTests != 5 {
		t.Errorf("expected TotalTests 5, got %d", summary.TotalTests)
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected VerifiedCount 1, got %d", summary.VerifiedCount)
	}
	if summary.CandidateCount != 1 {
		t.Errorf("expected CandidateCount 1, got %d", summary.CandidateCount)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected NotVulnerableCount 1, got %d", summary.NotVulnerableCount)
	}
	if summary.InconclusiveCount != 1 {
		t.Errorf("expected InconclusiveCount 1, got %d", summary.InconclusiveCount)
	}
	if summary.BlockedCount != 1 {
		t.Errorf("expected BlockedCount 1, got %d", summary.BlockedCount)
	}
	if summary.CategoriesCovered != 4 {
		t.Errorf("expected CategoriesCovered 4, got %d", summary.CategoriesCovered)
	}

	adminCov := summary.CoverageMap[string(CategoryBFLAAdminEndpoint)]
	if adminCov.Status != CoverageVerifiedIssueFound {
		t.Errorf("expected CoverageVerifiedIssueFound for admin endpoint, got %s", adminCov.Status)
	}
	if adminCov.Verified != 1 || adminCov.TestsRun != 2 {
		t.Errorf("unexpected admin coverage counts: %+v", adminCov)
	}
}
