package bopla

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
		ID:                  "auth-bopla-test",
		AuthorizingParty:    "Chief Information Security Officer",
		AuthorizationMethod: "Written",
		Status:              "APPROVED",
		ValidFrom:           &past,
		ValidUntil:          &future,
	}
}

// 1. Authorized identity sees protected property, lower-privilege does not -> NOT_VULNERABLE
func TestBOPLA_Read_ProperlyEnforced_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")

		if strings.Contains(authHdr, "token_admin") {
			// Admin sees compensation
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"u1","username":"alice","salary":120000}`)
			return
		}

		// Standard user response omits salary
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"u1","username":"alice"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "salary-read",
				Name:                    "User Salary Read",
				Endpoint:                "/api/users/profile",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "salary",
				ExpectedAccess:          ExpectedOmitted,
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

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when property omitted for user, got %s", results[0].VerificationState)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected summary NotVulnerableCount 1, got %d", summary.NotVulnerableCount)
	}
}

// 2. Lower-privilege identity unexpectedly receives protected property -> VERIFIED
func TestBOPLA_Read_PropertyExposed_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Server leaks salary to both admin and regular user!
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"u1","username":"alice","salary":120000}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "salary-read",
				Name:                    "User Salary Read",
				Endpoint:                "/api/users/profile",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "salary",
				ExpectedAccess:          ExpectedOmitted,
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

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED when protected property exposed to lower-privilege, got %s", results[0].VerificationState)
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected summary VerifiedCount 1, got %d", summary.VerifiedCount)
	}
	if results[0].Finding == nil {
		t.Errorf("expected finding attached to VERIFIED result")
	}
}

// 3. Nested sensitive property exposure -> VERIFIED
func TestBOPLA_Read_NestedPropertyExposure_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"user":{"profile":{"account":{"internal_tenant_id":"tenant-998877"}}}}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "nested-tenant-read",
				Name:                    "Nested Tenant ID Exposure",
				Endpoint:                "/api/account/details",
				Method:                  "GET",
				Category:                CategoryBOPLAExcessiveExposure,
				PropertyPath:            "user.profile.account.internal_tenant_id",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED for nested property exposure, got %s", results[0].VerificationState)
	}
}

// 4. Array item property exposure -> VERIFIED
func TestBOPLA_Read_ArrayPropertyExposure_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"accounts":[{"id":"acc-1","balance":500000},{"id":"acc-2","balance":1000}]}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "array-balance-read",
				Name:                    "Array Account Balance Read",
				Endpoint:                "/api/accounts",
				Method:                  "GET",
				Category:                CategoryBOPLARepresentationBypass,
				PropertyPath:            "accounts[0].balance",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED for array property exposure, got %s", results[0].VerificationState)
	}
}

// 5. Masked property properly masked -> NOT_VULNERABLE
func TestBOPLA_Read_MaskedProperty_ProperlyMasked_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "token_admin") {
			// Admin sees cleartext
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"card_number":"4111222233334444"}`)
			return
		}
		// User sees masked card number
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"card_number":"************4444"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "masked-card-read",
				Name:                    "Masked Card Number Check",
				Endpoint:                "/api/billing/card",
				Method:                  "GET",
				Category:                CategoryBOPLAExcessiveExposure,
				PropertyPath:            "card_number",
				ExpectedAccess:          ExpectedMasked,
				MaskPattern:             "****",
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
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when property is properly masked, got %s", results[0].VerificationState)
	}
}

// 6. Masked property unmasked (excessive data exposure) -> VERIFIED
func TestBOPLA_Read_MaskedProperty_UnmaskedCleartext_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Server returns cleartext card to both identities!
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"card_number":"4111222233334444"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "masked-card-read",
				Name:                    "Masked Card Number Check",
				Endpoint:                "/api/billing/card",
				Method:                  "GET",
				Category:                CategoryBOPLAExcessiveExposure,
				PropertyPath:            "card_number",
				ExpectedAccess:          ExpectedMasked,
				MaskPattern:             "****",
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED when property expected to be masked was cleartext, got %s", results[0].VerificationState)
	}
}

// 7. Explicit null value (withheld) -> NOT_VULNERABLE
func TestBOPLA_Read_ExplicitNull_Withheld_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "token_admin") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"ssn":"123-45-6789"}`)
			return
		}
		// Server explicitly withholds ssn as null
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ssn":null}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "ssn-read",
				Name:                    "SSN Read Check",
				Endpoint:                "/api/identity/ssn",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "ssn",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when property was withheld as null, got %s", results[0].VerificationState)
	}
}

// 8. Missing authorized baseline -> INCONCLUSIVE
func TestBOPLA_Read_MissingBaseline_Inconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "token_admin") {
			// Baseline fails with 500 error
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"database unavailable"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"salary":100000}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "salary-read",
				Name:                    "User Salary Read",
				Endpoint:                "/api/users/profile",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "salary",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when baseline fails, got %s", results[0].VerificationState)
	}
}

// 9. Baseline property missing from response -> INCONCLUSIVE
func TestBOPLA_Read_BaselinePropertyMissing_Inconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Neither admin nor user has property "non_existent_field"
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"username":"alice"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "non-existent-read",
				Name:                    "Non-Existent Property Read",
				Endpoint:                "/api/users/profile",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "non_existent_field",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when property absent from baseline, got %s", results[0].VerificationState)
	}
}

// 10. Write mutation blocked by default (AllowStateChangingTests: false) -> SKIPPED (0 requests)
func TestBOPLA_Write_BlockedByDefault_Skipped(t *testing.T) {
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
		AllowStateChangingTests: false, // Default: blocked
		SyntheticFixture:        true,
		Policies: []PropertyPolicy{
			{
				PropertyID:      "role-mutation",
				Name:            "Role Mutation Test",
				Endpoint:        "/api/users/profile",
				Method:          "PUT",
				Category:        CategoryBOPLAPropertyWrite,
				PropertyPath:    "role",
				MutationValue:   "admin",
				IsStateChanging: true,
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
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED when AllowStateChangingTests is false, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("security violation: dispatched %d requests for un-opted state-changing test", atomic.LoadInt32(&requestCount))
	}
}

// 11. Write mutation blocked when SyntheticFixture is false -> SKIPPED (0 requests)
func TestBOPLA_Write_BlockedWhenNotSyntheticFixture_Skipped(t *testing.T) {
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
		AllowStateChangingTests: true,  // Opt-in given
		SyntheticFixture:        false, // BUT not a designated synthetic fixture
		Policies: []PropertyPolicy{
			{
				PropertyID:      "role-mutation",
				Name:            "Role Mutation Test",
				Endpoint:        "/api/users/profile",
				Method:          "PUT",
				Category:        CategoryBOPLAPropertyWrite,
				PropertyPath:    "role",
				MutationValue:   "admin",
				IsStateChanging: true,
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
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED when SyntheticFixture is false, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("security violation: dispatched %d requests on non-synthetic fixture", atomic.LoadInt32(&requestCount))
	}
}

// 12. Write mutation: 200 OK echo alone without read-back confirmation -> CANDIDATE (never VERIFIED)
func TestBOPLA_Write_EchoAloneWithoutReadBack_Candidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			// Baseline succeeds
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"u1","role":"user"}`)
			return
		}
		if r.Method == "PUT" {
			// Server echoes request body with 200 OK
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"u1","role":"admin"}`)
			return
		}
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
		Policies: []PropertyPolicy{
			{
				PropertyID:       "role-mutation",
				Name:             "Role Mutation Test",
				Endpoint:         "/api/users/profile",
				Method:           "PUT",
				Category:         CategoryBOPLAPropertyWrite,
				PropertyPath:     "role",
				MutationValue:    "admin",
				ReadBackEndpoint: "", // No read-back endpoint configured
				IsStateChanging:  true,
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
	if results[0].VerificationState != StateCandidate {
		t.Errorf("expected CANDIDATE when write succeeds without independent read-back, got %s", results[0].VerificationState)
	}
}

// 13. Write mutation confirmed persisted via independent read-back -> VERIFIED
func TestBOPLA_Write_ReadBackConfirmed_Verified(t *testing.T) {
	var currentRole = "user"
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()

		if r.Method == "PUT" {
			// Server vulnerably updates currentRole!
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if rVal, ok := body["role"]; ok {
				currentRole = fmt.Sprintf("%v", rVal)
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"updated","role":"%s"}`, currentRole)
			return
		}

		if r.Method == "GET" {
			// Read-back returns persisted currentRole
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":"u1","role":"%s"}`, currentRole)
			return
		}
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
		Policies: []PropertyPolicy{
			{
				PropertyID:       "role-mutation",
				Name:             "Role Mutation Test",
				Endpoint:         "/api/users/profile",
				Method:           "PUT",
				Category:         CategoryBOPLAPropertyWrite,
				PropertyPath:     "role",
				MutationValue:    "admin",
				ReadBackEndpoint: "/api/users/profile",
				ReadBackMethod:   "GET",
				IsStateChanging:  true,
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED when independent read-back confirms mutation, got %s", results[0].VerificationState)
	}
	if results[0].Finding == nil {
		t.Errorf("expected finding attached to VERIFIED mutation result")
	}
}

// 14. Write mutation: Server returns 200 OK, but read-back confirms property was NOT changed (safely ignored) -> NOT_VULNERABLE
func TestBOPLA_Write_SafelyIgnored_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" {
			// Server accepts write request (200 OK), but silently ignores unauthorized role modification!
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"profile updated"}`)
			return
		}
		if r.Method == "GET" {
			// Read-back confirms role remained "user"
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"u1","role":"user"}`)
			return
		}
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
		Policies: []PropertyPolicy{
			{
				PropertyID:       "role-mutation",
				Name:             "Role Mutation Test",
				Endpoint:         "/api/users/profile",
				Method:           "PUT",
				Category:         CategoryBOPLAPropertyWrite,
				PropertyPath:     "role",
				MutationValue:    "admin",
				ReadBackEndpoint: "/api/users/profile",
				ReadBackMethod:   "GET",
				IsStateChanging:  true,
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
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when backend safely ignored unauthorized property, got %s", results[0].VerificationState)
	}
}

// 15. Write mutation rejected by server with 403 Forbidden -> NOT_VULNERABLE
func TestBOPLA_Write_ServerRejected_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"role":"user"}`)
			return
		}
		// Server rejects PUT with 403 Forbidden
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"role cannot be modified by standard users"}`)
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
		Policies: []PropertyPolicy{
			{
				PropertyID:      "role-mutation",
				Name:            "Role Mutation Test",
				Endpoint:        "/api/users/profile",
				Method:          "PUT",
				Category:        CategoryBOPLAPropertyWrite,
				PropertyPath:    "role",
				MutationValue:   "admin",
				IsStateChanging: true,
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
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when server rejects mutation with 403, got %s", results[0].VerificationState)
	}
}

// 16. Mass Assignment: verified when injected property confirmed persisted via read-back -> VERIFIED
func TestBOPLA_MassAssignment_Verified(t *testing.T) {
	var isAdmin = false
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()

		if r.Method == "POST" && r.URL.Path == "/api/register" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["is_admin"]; ok && v == true {
				isAdmin = true
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"usr-99","msg":"registered"}`)
			return
		}

		if r.Method == "GET" && r.URL.Path == "/api/me" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":"usr-99","is_admin":%v}`, isAdmin)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
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
		Policies: []PropertyPolicy{
			{
				PropertyID:       "register-mass-assignment",
				Name:             "Registration Mass Assignment",
				Endpoint:         "/api/register",
				Method:           "POST",
				Category:         CategoryBOPLAMassAssignment,
				PropertyPath:     "is_admin",
				MutationValue:    true,
				ReadBackEndpoint: "/api/me",
				ReadBackMethod:   "GET",
				IsStateChanging:  true,
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED for confirmed mass assignment, got %s", results[0].VerificationState)
	}
	if results[0].Category != CategoryBOPLAMassAssignment {
		t.Errorf("expected CategoryBOPLAMassAssignment, got %s", results[0].Category)
	}
}

// 17. Scope check: excluded endpoint dispatches zero requests -> SKIPPED
func TestBOPLA_Scope_ExcludedEndpoint_Skipped(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
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
			return strings.Contains(target, "/api/secret")
		},
		Policies: []PropertyPolicy{
			{
				PropertyID:   "secret-read",
				Name:         "Secret Endpoint Check",
				Endpoint:     "/api/secret/data",
				Method:       "GET",
				Category:     CategoryBOPLAPropertyRead,
				PropertyPath: "key",
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
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED for excluded endpoint, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("security violation: dispatched %d requests to excluded target", atomic.LoadInt32(&requestCount))
	}
}

// 18. Request Budget CAS Enforcement: dispatches stop when budget reached
func TestBOPLA_RequestBudget_Enforcement(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"salary":1000}`)
	}))
	defer ts.Close()

	var dispatched int32
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:       "asm-01",
		ExecutionID:        "exec-01",
		BaseURL:            ts.URL,
		Authorization:      testApprovedAuth(),
		MaxRequests:        2, // strictly allow max 2 requests
		DispatchedRequests: &dispatched,
		Policies: []PropertyPolicy{
			{PropertyID: "p1", Name: "P1", Endpoint: "/p1", Method: "GET", PropertyPath: "salary", Category: CategoryBOPLAPropertyRead},
			{PropertyID: "p2", Name: "P2", Endpoint: "/p2", Method: "GET", PropertyPath: "salary", Category: CategoryBOPLAPropertyRead},
			{PropertyID: "p3", Name: "P3", Endpoint: "/p3", Method: "GET", PropertyPath: "salary", Category: CategoryBOPLAPropertyRead},
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

	curDispatched := atomic.LoadInt32(&dispatched)
	if curDispatched > 2 {
		t.Errorf("budget exceeded: dispatched %d requests, limit was 2", curDispatched)
	}
	// At least 1 result should report budget exceeded error
	hasBudgetInconclusive := false
	for _, r := range results {
		if strings.Contains(r.EvidenceSummary, "budget exceeded") {
			hasBudgetInconclusive = true
			break
		}
	}
	if !hasBudgetInconclusive {
		t.Errorf("expected at least one test to record budget exceeded")
	}
}

// 19. Cross-origin redirect credential stripping
func TestBOPLA_Redirect_CrossHostCredentialStripping(t *testing.T) {
	var targetReceivedAuth bool

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			targetReceivedAuth = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"salary":9999}`)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       redirectServer.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "redirect-read",
				Name:                    "Redirect Test",
				Endpoint:                "/redirect",
				Method:                  "GET",
				Category:                CategoryBOPLAPropertyRead,
				PropertyPath:            "salary",
				ExpectedAccess:          ExpectedOmitted,
				AllowedRoles:            []string{"admin"},
				RestrictedRoles:         []string{"user"},
				PositiveControlRequired: true,
			},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer secret_admin_token"}},
			{Alias: "user", Role: "user", Headers: map[string]string{"Authorization": "Bearer secret_user_token"}},
		},
	}

	_, _, _ = engine.Assess(context.Background(), actx)

	if targetReceivedAuth {
		t.Errorf("security violation: sensitive credentials leaked across cross-origin redirect")
	}
}

// 20. Dry-Run Plan: Zero network traffic and accurate counts
func TestBOPLA_DryRunPlan_ZeroRequests(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-dry-01",
		BaseURL:                 ts.URL,
		AllowStateChangingTests: false,
		Policies:                DefaultPolicies(),
		Identities:              DefaultIdentities(),
		DryRun:                  true,
	}

	plan, err := engine.Plan(context.Background(), actx)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("dry-run plan dispatched %d requests; must dispatch zero", atomic.LoadInt32(&requestCount))
	}
	if plan.TotalTests != 5 {
		t.Errorf("expected 5 default planned tests, got %d", plan.TotalTests)
	}
	if plan.StateChangingTests == 0 {
		t.Errorf("expected state-changing tests identified in plan")
	}
}

// 21. Identical identities -> INCONCLUSIVE
func TestBOPLA_IdenticalIdentities_Inconclusive(t *testing.T) {
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
		Policies: []PropertyPolicy{
			{PropertyID: "p1", Name: "P1", Endpoint: "/api/test", Method: "GET", PropertyPath: "role", Category: CategoryBOPLAPropertyRead},
		},
		Identities: []TestIdentity{
			{Alias: "same_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer same_token"}},
			{Alias: "same_user", Role: "user", Headers: map[string]string{"Authorization": "Bearer same_token"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE for identical identities, got %s", results[0].VerificationState)
	}
}

// 22. ExtractProperty unit tests: dot notation, arrays, case insensitivity, missing paths
func TestBOPLA_ExtractProperty_UnitTests(t *testing.T) {
	jsonBlob := []byte(`{
		"id": 101,
		"username": "bob",
		"Profile": {
			"Role": "admin",
			"Salary": 95000.50,
			"Active": true
		},
		"permissions": ["read", "write", "admin"],
		"items": [
			{"code": "item-A", "price": 10.5},
			{"code": "item-B", "price": 20.0}
		]
	}`)

	var data any
	if err := json.Unmarshal(jsonBlob, &data); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// 1. Top-level scalar
	val, found := ExtractProperty(data, "username")
	if !found || val != "bob" {
		t.Errorf("expected 'bob', got %v (found: %v)", val, found)
	}

	// 2. Nested dot notation
	val, found = ExtractProperty(data, "Profile.Role")
	if !found || val != "admin" {
		t.Errorf("expected 'admin', got %v (found: %v)", val, found)
	}

	// 3. Case-insensitive key lookup
	val, found = ExtractProperty(data, "profile.salary")
	if !found || val != 95000.50 {
		t.Errorf("expected 95000.50, got %v (found: %v)", val, found)
	}

	// 4. Array index scalar
	val, found = ExtractProperty(data, "permissions[0]")
	if !found || val != "read" {
		t.Errorf("expected 'read', got %v (found: %v)", val, found)
	}

	// 5. Array index of objects
	val, found = ExtractProperty(data, "items[1].code")
	if !found || val != "item-B" {
		t.Errorf("expected 'item-B', got %v (found: %v)", val, found)
	}

	// 6. Missing property
	_, found = ExtractProperty(data, "non.existent.path")
	if found {
		t.Errorf("expected false for nonexistent path")
	}

	// 7. Out of bound array index
	_, found = ExtractProperty(data, "permissions[99]")
	if found {
		t.Errorf("expected false for out-of-bound array index")
	}
}

// 23. IsPropertyEqual unit tests: scalar comparisons, types, floats
func TestBOPLA_IsPropertyEqual_UnitTests(t *testing.T) {
	if !IsPropertyEqual("admin", "admin") {
		t.Errorf("expected string equality")
	}
	if !IsPropertyEqual("Admin", "admin") {
		t.Errorf("expected case-insensitive string equality")
	}
	if !IsPropertyEqual(true, "true") {
		t.Errorf("expected bool equality across bool and string")
	}
	if !IsPropertyEqual(float64(42), 42) {
		t.Errorf("expected numeric equality across float64 and int")
	}
	if IsPropertyEqual("admin", "user") {
		t.Errorf("expected false for different strings")
	}
	if IsPropertyEqual(nil, "something") {
		t.Errorf("expected false when one is nil")
	}
}

// 24. RedactValue unit tests: masks sensitive values in evidence
func TestBOPLA_RedactValue_UnitTests(t *testing.T) {
	redacted := RedactValue("secret_salary_150k")
	if strings.Contains(redacted, "salary") {
		t.Errorf("sensitive value was not properly redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "****") {
		t.Errorf("expected mask asterisks in redacted value: %s", redacted)
	}
}

// 25. Representation Bypass: top-level restricted but nested exposed -> VERIFIED
func TestBOPLA_RepresentationBypass_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Top-level "role" is omitted, but nested "meta.assigned_role" exposes admin role
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"username":"bob","meta":{"assigned_role":"admin"}}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Policies: []PropertyPolicy{
			{
				PropertyID:              "bypass-assigned-role",
				Name:                    "Representation Bypass Role",
				Endpoint:                "/api/users/me",
				Method:                  "GET",
				Category:                CategoryBOPLARepresentationBypass,
				PropertyPath:            "meta.assigned_role",
				ExpectedAccess:          ExpectedOmitted,
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
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED for representation bypass, got %s", results[0].VerificationState)
	}
}

// 26. Both flags set against a target that is NOT an authorized fixture dispatch zero mutation requests
func TestBOPLA_Write_BlockedWhenTargetNotAuthorizedFixture_ZeroRequests(t *testing.T) {
	var dispatchedCount int32
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-prod-01",
		ExecutionID:             "exec-prod-01",
		BaseURL:                 "https://api.production.corp.acme.com", // Arbitrary production target!
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: true, // Both flags explicitly set!
		SyntheticFixture:        true,
		DispatchedRequests:      &dispatchedCount,
		Policies: []PropertyPolicy{
			{
				PropertyID:      "role-mutation",
				Name:            "Role Mutation Test",
				Endpoint:        "/api/users/profile",
				Method:          "PUT",
				Category:        CategoryBOPLAPropertyWrite,
				PropertyPath:    "role",
				MutationValue:   "admin",
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
		t.Errorf("security invariant violated: expected SKIPPED when target is not an authorized fixture, got %s", results[0].VerificationState)
	}
	if !strings.Contains(results[0].EvidenceSummary, "not an authorized synthetic fixture") {
		t.Errorf("expected evidence summary to state target is not an authorized fixture, got: %s", results[0].EvidenceSummary)
	}
	if atomic.LoadInt32(&dispatchedCount) != 0 {
		t.Errorf("security invariant violated: dispatched %d network requests against arbitrary production target", atomic.LoadInt32(&dispatchedCount))
	}
}

// 27. Valid isolated fixture with explicit opt-in executes ONLY the configured mutation
func TestBOPLA_Write_ValidIsolatedFixture_ExecutesConfiguredMutationOnly(t *testing.T) {
	var putCount int32
	var getCount int32
	var currentRole = "user"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" {
			atomic.AddInt32(&putCount, 1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if rVal, ok := body["role"]; ok {
				currentRole = fmt.Sprintf("%v", rVal)
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"updated","role":"%s"}`, currentRole)
			return
		}
		if r.Method == "GET" {
			atomic.AddInt32(&getCount, 1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":"u1","role":"%s"}`, currentRole)
			return
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-fixture-01",
		ExecutionID:             "exec-fixture-01",
		BaseURL:                 ts.URL, // Valid local synthetic fixture (loopback)
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		Policies: []PropertyPolicy{
			{
				PropertyID:       "role-mutation",
				Name:             "Role Mutation Test",
				Endpoint:         "/api/users/profile",
				Method:           "PUT",
				Category:         CategoryBOPLAPropertyWrite,
				PropertyPath:     "role",
				MutationValue:    "admin",
				ReadBackEndpoint: "/api/users/profile",
				ReadBackMethod:   "GET",
				IsStateChanging:  true,
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
		t.Errorf("expected VERIFIED on valid fixture, got %s", results[0].VerificationState)
	}
	if atomic.LoadInt32(&putCount) != 1 {
		t.Errorf("expected exactly 1 PUT write mutation request, got %d", atomic.LoadInt32(&putCount))
	}
}

// 28. Failed or uncertain mutation is NEVER retried automatically
func TestBOPLA_Write_FailedOrUncertainMutation_NoRetries(t *testing.T) {
	var putCount int32
	var deleteCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" {
			atomic.AddInt32(&putCount, 1)
			// Server encounters an internal error / failure
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"database failure during mutation"}`)
			return
		}
		if r.Method == "DELETE" {
			atomic.AddInt32(&deleteCount, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"u1","role":"user"}`)
			return
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-fail-01",
		ExecutionID:             "exec-fail-01",
		BaseURL:                 ts.URL,
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		Policies: []PropertyPolicy{
			{
				PropertyID:      "role-mutation",
				Name:            "Role Mutation Test",
				Endpoint:        "/api/users/profile",
				Method:          "PUT",
				Category:        CategoryBOPLAPropertyWrite,
				PropertyPath:    "role",
				MutationValue:   "admin",
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
	// PUT must be attempted exactly once
	if atomic.LoadInt32(&putCount) != 1 {
		t.Errorf("expected exactly 1 PUT write attempt, got %d", atomic.LoadInt32(&putCount))
	}
	// Alternate write methods (e.g. DELETE) must never be attempted
	if atomic.LoadInt32(&deleteCount) != 0 {
		t.Errorf("security violation: engine dispatched DELETE request after PUT failed; write retries must not occur across write methods")
	}
	// Result must not be VERIFIED
	if results[0].VerificationState == StateVerified {
		t.Errorf("failed mutation must not be VERIFIED, got %s", results[0].VerificationState)
	}
}
