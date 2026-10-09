package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setupMockServer creates a mock HTTP server with configurable authorization behavior.
func setupMockServer() *httptest.Server {
	mux := http.NewServeMux()

	// 1. Orders API (BOLA & Shared resource tests)
	mux.HandleFunc("/api/orders/order_alice_101", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "alice") {
			// Owner Alice accessing own order
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"order_id": "order_alice_101", "owner": "user_a", "amount": 100}`))
			return
		}
		if strings.Contains(authHdr, "bob") {
			// Bob accessing Alice's order -> Simulated BOLA VULNERABILITY!
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"order_id": "order_alice_101", "owner": "user_a", "amount": 100}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/api/orders/order_bob_202", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "bob") {
			// Bob accessing own order
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"order_id": "order_bob_202", "owner": "user_b", "amount": 250}`))
			return
		}
		if strings.Contains(authHdr, "alice") {
			// Alice accessing Bob's order -> Properly ENFORCED rejection (HTTP 403)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error": "access denied"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/api/orders/order_shared_303", func(w http.ResponseWriter, r *http.Request) {
		// Shared resource between Alice and Bob
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"order_id": "order_shared_303", "shared": true, "items": ["item1"]}`))
	})

	mux.HandleFunc("/api/orders/order_empty_404", func(w http.ResponseWriter, r *http.Request) {
		// Returns 200 OK but empty payload
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	// 2. Admin API (BFLA tests)
	mux.HandleFunc("/api/admin/system/export", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "admin") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "exported", "records": 500}`))
			return
		}
		// Denied for normal users
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error": "admin privileges required"}`))
	})

	mux.HandleFunc("/api/admin/users/delete", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "bob") {
			// Simulated BFLA VULNERABILITY! Bob (unprivileged) calls admin endpoint and succeeds!
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted": true, "user": "target_user"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// 3. Profiles API (BOPLA Exposure tests)
	mux.HandleFunc("/api/profiles/profile_alice", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "bob") {
			// Bob reading Alice's profile -> Exposes sensitive internal property "credit_score"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name": "Alice", "credit_score": 820, "public_bio": "Hello"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name": "Alice", "credit_score": 820, "public_bio": "Hello"}`))
	})

	mux.HandleFunc("/api/profiles/profile_bob", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "alice") {
			// Alice reading Bob's profile -> Sensitive property "credit_score" correctly REDACTED/OMITTED
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name": "Bob", "public_bio": "Hi there"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// 4. User Settings API (BOPLA Modification tests)
	mux.HandleFunc("/api/users/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" || r.Method == "POST" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)

			// If client attempts to change role to "admin"
			if val, ok := body["role"]; ok && val == "admin" {
				authHdr := r.Header.Get("Authorization")
				if strings.Contains(authHdr, "bob") {
					// Simulated BOPLA Modification VULNERABILITY: Server accepts role mutation!
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"user": "bob", "role": "admin"}`))
					return
				}
				// Rejected for Alice
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "cannot change role"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

func getTestPolicy() *AuthzPolicy {
	return &AuthzPolicy{
		AssessmentRef:    "ASM-TEST-AUTHZ",
		AuthorizationDoc: "DOC-AUTHZ-TEST",
		AllowWriteTests:  true,
		Identities: map[string]TestIdentity{
			"user_a": {
				Alias:          "user_a",
				Role:           "user",
				TenantID:       "tenant_1",
				PrivilegeLevel: 1,
				Headers:        map[string]string{"Authorization": "Bearer alice_token_secret"},
			},
			"user_b": {
				Alias:          "user_b",
				Role:           "user",
				TenantID:       "tenant_2",
				PrivilegeLevel: 1,
				Headers:        map[string]string{"Authorization": "Bearer bob_token_secret"},
			},
			"admin_user": {
				Alias:          "admin_user",
				Role:           "admin",
				TenantID:       "tenant_1",
				PrivilegeLevel: 5,
				Headers:        map[string]string{"Authorization": "Bearer admin_master_token"},
			},
		},
		Resources: map[string]TestResource{
			"order_alice_101": {
				ID:                  "order_alice_101",
				Type:                "order",
				OwnerAlias:          "user_a",
				TenantID:            "tenant_1",
				SensitiveProperties: []string{"amount"},
			},
			"order_bob_202": {
				ID:                  "order_bob_202",
				Type:                "order",
				OwnerAlias:          "user_b",
				TenantID:            "tenant_2",
				SensitiveProperties: []string{"amount"},
			},
			"order_shared_303": {
				ID:                "order_shared_303",
				Type:              "order",
				OwnerAlias:        "user_a",
				TenantID:          "tenant_1",
				IsShared:          true,
				AllowedIdentities: []string{"user_b"},
			},
			"profile_alice": {
				ID:                  "profile_alice",
				Type:                "profile",
				OwnerAlias:          "user_a",
				TenantID:            "tenant_1",
				SensitiveProperties: []string{"credit_score"},
			},
			"profile_bob": {
				ID:                  "profile_bob",
				Type:                "profile",
				OwnerAlias:          "user_b",
				TenantID:            "tenant_2",
				SensitiveProperties: []string{"credit_score"},
			},
		},
		Endpoints: []EndpointRule{
			{
				Pattern:      "/api/admin/system/export",
				Method:       "GET",
				AllowedRoles: []string{"admin"},
				AdminOnly:    true,
			},
			{
				Pattern:      "/api/admin/users/delete",
				Method:       "POST",
				AllowedRoles: []string{"admin"},
				AdminOnly:    true,
			},
			{
				Pattern:             "/api/users/profile",
				Method:              "PUT",
				MonitoredProperties: []string{"role"},
			},
		},
	}
}

func TestBOLA_EnforcementAndVulnerability(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	engine := NewEngine(server.Client())

	results, findings, summary, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	// 1. Check BOLA Vulnerability on Alice's Order accessed by Bob
	var verifiedBOLA *AuthzTestResult
	var enforcedBOLA *AuthzTestResult
	for i := range results {
		r := &results[i]
		if r.Category == CategoryBOLA && r.TargetResource == "order_alice_101" && r.PrimaryIdentity == "user_b" {
			verifiedBOLA = r
		}
		if r.Category == CategoryBOLA && r.TargetResource == "order_bob_202" && r.PrimaryIdentity == "user_a" {
			enforcedBOLA = r
		}
	}

	if verifiedBOLA == nil {
		t.Fatalf("expected BOLA test case for Bob accessing Alice's order")
	}
	if verifiedBOLA.VerificationState != StateVerified {
		t.Errorf("expected StateVerified for vulnerable BOLA order access, got %s", verifiedBOLA.VerificationState)
	}
	if !verifiedBOLA.DisclosedData {
		t.Errorf("expected DisclosedData to be true for verified BOLA")
	}

	// 2. Check correctly enforced BOLA on Bob's order accessed by Alice
	if enforcedBOLA == nil {
		t.Fatalf("expected BOLA test case for Alice accessing Bob's order")
	}
	if enforcedBOLA.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for denied access (HTTP 403), got %s", enforcedBOLA.VerificationState)
	}

	// Verify finding generation
	foundBOLAFinding := false
	for _, f := range findings {
		if strings.Contains(f.Category, "Broken Object Level Authorization") {
			foundBOLAFinding = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH severity for BOLA finding, got %s", f.Severity)
			}
			if f.Verification.Status != "VERIFIED" {
				t.Errorf("expected VERIFIED status for BOLA finding, got %s", f.Verification.Status)
			}
		}
	}
	if !foundBOLAFinding {
		t.Errorf("expected BOLA finding in report findings")
	}

	if summary.VerifiedCount == 0 {
		t.Errorf("expected summary.VerifiedCount > 0, got %d", summary.VerifiedCount)
	}
}

func TestBFLA_EnforcementAndVulnerability(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	engine := NewEngine(server.Client())

	results, _, _, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	var enforcedAdminExport *AuthzTestResult
	var vulnerableAdminDelete *AuthzTestResult

	for i := range results {
		r := &results[i]
		if r.Category == CategoryBFLA && strings.Contains(r.Endpoint, "/api/admin/system/export") && r.PrimaryIdentity == "user_a" {
			enforcedAdminExport = r
		}
		if r.Category == CategoryBFLA && strings.Contains(r.Endpoint, "/api/admin/users/delete") && r.PrimaryIdentity == "user_b" {
			vulnerableAdminDelete = r
		}
	}

	if enforcedAdminExport == nil {
		t.Fatalf("expected BFLA test for export endpoint")
	}
	if enforcedAdminExport.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for correctly denied admin endpoint, got %s", enforcedAdminExport.VerificationState)
	}

	if vulnerableAdminDelete == nil {
		t.Fatalf("expected BFLA test for delete endpoint")
	}
	if vulnerableAdminDelete.VerificationState != StateVerified {
		t.Errorf("expected StateVerified for vulnerable admin delete endpoint, got %s", vulnerableAdminDelete.VerificationState)
	}
}

func TestBOPLA_ExposureAndModification(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	engine := NewEngine(server.Client())

	results, _, _, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	var exposedCreditScore *AuthzTestResult
	var redactedCreditScore *AuthzTestResult
	var vulnerableRoleMutation *AuthzTestResult
	var rejectedRoleMutation *AuthzTestResult

	for i := range results {
		r := &results[i]
		if r.Category == CategoryBOPLAExposure && r.TargetResource == "profile_alice" && r.PrimaryIdentity == "user_b" {
			exposedCreditScore = r
		}
		if r.Category == CategoryBOPLAExposure && r.TargetResource == "profile_bob" && r.PrimaryIdentity == "user_a" {
			redactedCreditScore = r
		}
		if r.Category == CategoryBOPLAModification && r.PrimaryIdentity == "user_b" {
			vulnerableRoleMutation = r
		}
		if r.Category == CategoryBOPLAModification && r.PrimaryIdentity == "user_a" {
			rejectedRoleMutation = r
		}
	}

	// 1. Exposure test
	if exposedCreditScore == nil {
		t.Fatalf("expected BOPLA exposure test for Alice's profile")
	}
	if exposedCreditScore.VerificationState != StateVerified {
		t.Errorf("expected StateVerified for exposed sensitive property, got %s", exposedCreditScore.VerificationState)
	}

	if redactedCreditScore == nil {
		t.Fatalf("expected BOPLA exposure test for Bob's profile")
	}
	if redactedCreditScore.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for properly redacted sensitive property, got %s", redactedCreditScore.VerificationState)
	}

	// 2. Modification test
	if vulnerableRoleMutation == nil {
		t.Fatalf("expected BOPLA modification test for Bob")
	}
	if vulnerableRoleMutation.VerificationState != StateVerified {
		t.Errorf("expected StateVerified for accepted unauthorized role mutation, got %s", vulnerableRoleMutation.VerificationState)
	}

	if rejectedRoleMutation == nil {
		t.Fatalf("expected BOPLA modification test for Alice")
	}
	if rejectedRoleMutation.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for rejected role mutation (HTTP 403), got %s", rejectedRoleMutation.VerificationState)
	}
}

func TestWriteTest_SafetyGuardBlocksMutationsWhenDisabled(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	policy.AllowWriteTests = false // SAFETY GUARD ACTIVE!

	engine := NewEngine(server.Client())

	results, _, _, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	// Any mutating test case (PUT / POST) must NOT be executed and marked as Candidate
	for _, r := range results {
		if r.Method == "PUT" || r.Method == "POST" || r.Method == "DELETE" {
			if r.VerificationState == StateVerified {
				t.Errorf("SAFETY VIOLATION: Mutating test case %s %s was executed and verified while AllowWriteTests is false!", r.Method, r.Endpoint)
			}
			if !strings.Contains(r.EvidenceSummary, "write-test approval required") {
				t.Errorf("expected safety warning in evidence summary, got %s", r.EvidenceSummary)
			}
		}
	}
}

func TestSecretRedaction_EndToEnd(t *testing.T) {
	secretToken := "STAGE4_SECRET_BEARER_TOKEN_99A1"
	secretPass := "STAGE4_SECRET_PASSWORD_33B2"
	rawURL := "https://example.com/api/orders?token=" + secretToken + "&user=test"

	// 1. URL Redaction
	cleanURL := SanitizeURL(rawURL)
	if strings.Contains(cleanURL, secretToken) {
		t.Errorf("LEAK: SanitizeURL leaked sensitive query parameter: %s", cleanURL)
	}

	// 2. Header Redaction
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+secretToken)
	headers.Set("Cookie", "session="+secretPass)
	scrubbed := SanitizeHeaders(headers)
	for _, v := range scrubbed {
		if strings.Contains(v, secretToken) || strings.Contains(v, secretPass) {
			t.Errorf("LEAK: SanitizeHeaders leaked secret: %s", v)
		}
	}

	// 3. Body / JSON Redaction
	jsonBody := []byte(`{"user": "alice", "password": "` + secretPass + `", "token": "` + secretToken + `"}`)
	redactedBody := RedactBody(jsonBody, 200)
	if strings.Contains(redactedBody, secretToken) || strings.Contains(redactedBody, secretPass) {
		t.Errorf("LEAK: RedactBody leaked secret: %s", redactedBody)
	}

	// 4. Policy SafeMetadata serialization
	policy := getTestPolicy()
	safeJSON := policy.SafeMetadata()
	if strings.Contains(safeJSON, "alice_token_secret") || strings.Contains(safeJSON, "bob_token_secret") || strings.Contains(safeJSON, "admin_master_token") {
		t.Errorf("LEAK: SafeMetadata leaked runtime authorization headers: %s", safeJSON)
	}
}

func TestScopeAndExclusion_Enforcement(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	engine := NewEngine(server.Client())

	// Exclude all admin endpoints
	isExcluded := func(u string) bool {
		return strings.Contains(u, "/api/admin/")
	}
	isAllowed := func(u string) bool {
		return strings.HasPrefix(u, server.URL)
	}

	results, _, _, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		isAllowed,
		isExcluded,
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	for _, r := range results {
		if strings.Contains(r.Endpoint, "/api/admin/") {
			if r.VerificationState == StateVerified {
				t.Errorf("SCOPE VIOLATION: Excluded admin endpoint was executed and verified: %s", r.Endpoint)
			}
		}
	}
}

func TestSharedResource_AccessPermitted(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	policy := getTestPolicy()
	engine := NewEngine(server.Client())

	results, _, _, err := engine.Execute(
		context.Background(),
		server.URL,
		policy,
		"asm-101",
		"exec-101",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine.Execute failed: %v", err)
	}

	var sharedResult *AuthzTestResult
	for i := range results {
		r := &results[i]
		if r.TargetResource == "order_shared_303" && r.PrimaryIdentity == "user_b" {
			sharedResult = r
			break
		}
	}

	if sharedResult == nil {
		t.Fatalf("expected test result for shared resource order_shared_303")
	}
	if sharedResult.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for legitimately shared resource, got %s", sharedResult.VerificationState)
	}
}

func TestFalsePositive_EmptyBodyAndGenericErrorInHTTP200(t *testing.T) {
	comparator := NewComparator()

	// 1. Empty body with HTTP 200 -> Must NOT be marked as Verified!
	tcEmpty := &AuthzTestCase{
		ID:              "tc-empty",
		Category:        CategoryBOLA,
		PrimaryIdentity: "user_b",
		TargetResource:  "order_empty_404",
		ExpectedResult:  ExpectedDeny,
	}
	respEmpty := &ResponseData{
		StatusCode: 200,
		Body:       []byte(`{}`),
	}
	resEmpty := &TestResource{ID: "order_empty_404", OwnerAlias: "user_a"}
	res1 := comparator.Compare(tcEmpty, respEmpty, nil, resEmpty)

	if res1.VerificationState == StateVerified {
		t.Errorf("FALSE POSITIVE: Empty HTTP 200 payload was marked as StateVerified!")
	}
	if res1.VerificationState != StateCandidate {
		t.Errorf("expected StateCandidate for empty HTTP 200, got %s", res1.VerificationState)
	}

	// 2. Generic error message disguised as HTTP 200
	tcError := &AuthzTestCase{
		ID:              "tc-err",
		Category:        CategoryBOLA,
		PrimaryIdentity: "user_b",
		TargetResource:  "order_priv",
		ExpectedResult:  ExpectedDeny,
	}
	respError := &ResponseData{
		StatusCode: 200,
		Body:       []byte(`{"status": "error", "message": "Access Denied: Insufficient permissions"}`),
	}
	res2 := comparator.Compare(tcError, respError, nil, &TestResource{ID: "order_priv", OwnerAlias: "user_a"})

	if res2.VerificationState == StateVerified {
		t.Errorf("FALSE POSITIVE: Application-level denial in HTTP 200 was marked as StateVerified!")
	}
	if res2.VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for app-level denial, got %s", res2.VerificationState)
	}
}

func TestPolicyValidation_RejectsInvalidPolicy(t *testing.T) {
	// 1. Empty identities
	p1 := &AuthzPolicy{
		Identities: map[string]TestIdentity{},
	}
	if err := p1.Validate(); err == nil {
		t.Errorf("expected error for empty identities policy")
	}

	// 2. Identity without role
	p2 := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"user_a": {Alias: "user_a", Role: ""},
		},
	}
	if err := p2.Validate(); err == nil {
		t.Errorf("expected error for identity without role")
	}

	// 3. Resource with unknown owner
	p3 := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"user_a": {Alias: "user_a", Role: "user"},
		},
		Resources: map[string]TestResource{
			"res_1": {ID: "res_1", OwnerAlias: "non_existent_user"},
		},
	}
	if err := p3.Validate(); err == nil {
		t.Errorf("expected error for unknown owner alias")
	}
}

func TestAuthz_ComprehensiveRedaction(t *testing.T) {
	// 1. Plain-text key-value pairs (form-urlencoded or plain text)
	plainText := "access_token=super_secret_token_123&client_secret=topsecret_password&api_key=sk_live_99999&username=alice"
	redactedText := RedactBody([]byte(plainText), 0)
	if strings.Contains(redactedText, "super_secret_token_123") {
		t.Errorf("plain text access_token leaked: %s", redactedText)
	}
	if strings.Contains(redactedText, "topsecret_password") {
		t.Errorf("plain text client_secret leaked: %s", redactedText)
	}
	if strings.Contains(redactedText, "sk_live_99999") {
		t.Errorf("plain text api_key leaked: %s", redactedText)
	}
	if !strings.Contains(redactedText, "username=alice") {
		t.Errorf("expected non-sensitive field preserved: %s", redactedText)
	}

	// 2. Bearer token in text
	bearerText := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	redactedBearer := RedactBody([]byte(bearerText), 0)
	if strings.Contains(redactedBearer, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") {
		t.Errorf("bearer token signature leaked: %s", redactedBearer)
	}

	// 3. Session cookies in headers / body
	cookieText := "Set-Cookie: connect.sid=s%3Aabc123xyz456; Path=/; HttpOnly\nSet-Cookie: PHPSESSID=session98765; Path=/"
	redactedCookie := RedactBody([]byte(cookieText), 0)
	if strings.Contains(redactedCookie, "s%3Aabc123xyz456") {
		t.Errorf("connect.sid cookie value leaked: %s", redactedCookie)
	}
	if strings.Contains(redactedCookie, "session98765") {
		t.Errorf("PHPSESSID cookie value leaked: %s", redactedCookie)
	}

	// 4. Standalone JWT anywhere in response
	jwtText := "Embedded JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123xyz456def789 in response"
	redactedJWT := RedactBody([]byte(jwtText), 0)
	if strings.Contains(redactedJWT, "abc123xyz456def789") {
		t.Errorf("standalone JWT leaked: %s", redactedJWT)
	}
	if !strings.Contains(redactedJWT, "[REDACTED_JWT]") {
		t.Errorf("expected [REDACTED_JWT] tag, got: %s", redactedJWT)
	}

	// 5. Query parameters in embedded URLs
	urlText := "Redirect URL: https://example.com/oauth/callback?token=secret_query_tok&user=bob"
	redactedURL := RedactBody([]byte(urlText), 0)
	if strings.Contains(redactedURL, "secret_query_tok") {
		t.Errorf("query token leaked: %s", redactedURL)
	}
	if !strings.Contains(redactedURL, "token=[REDACTED]") {
		t.Errorf("expected token=[REDACTED] in url: %s", redactedURL)
	}

	// 6. HTML password inputs
	htmlText := `<html><form><input type="password" name="passwd" value="superSecretPassword123"><input type="hidden" name="csrf_token" value="csrfSecretToken456"></form></html>`
	redactedHTML := RedactBody([]byte(htmlText), 0)
	if strings.Contains(redactedHTML, "superSecretPassword123") {
		t.Errorf("HTML password leaked: %s", redactedHTML)
	}
	if strings.Contains(redactedHTML, "csrfSecretToken456") {
		t.Errorf("HTML csrf token leaked: %s", redactedHTML)
	}

	// 7. PEM Private Key
	pemText := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzFakePrivateKeyBlockHere\n-----END RSA PRIVATE KEY-----"
	redactedPEM := RedactBody([]byte(pemText), 0)
	if strings.Contains(redactedPEM, "FakePrivateKeyBlockHere") {
		t.Errorf("PEM private key leaked: %s", redactedPEM)
	}
	if !strings.Contains(redactedPEM, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("expected [REDACTED_PRIVATE_KEY] tag, got: %s", redactedPEM)
	}

	// 8. Request summary redaction
	reqSummary := RedactRequestSummary("POST", "https://example.com/api/login?token=sensitive_query", map[string]string{
		"Authorization": "Bearer superSecret",
		"X-Custom":      "regular-value",
	}, `{"password": "secretPassword"}`)
	if strings.Contains(reqSummary, "sensitive_query") {
		t.Errorf("query secret leaked in request summary: %s", reqSummary)
	}
	if strings.Contains(reqSummary, "superSecret") {
		t.Errorf("authorization header leaked in request summary: %s", reqSummary)
	}
	if strings.Contains(reqSummary, "secretPassword") {
		t.Errorf("password leaked in request summary payload: %s", reqSummary)
	}
}

func TestAuthz_ScopedRedirectEnforcement(t *testing.T) {
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"leak": "data"}`))
	}))
	defer thirdParty.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/out-of-scope-redirect":
			http.Redirect(w, r, thirdParty.URL+"/leak", http.StatusFound)
		case "/excluded-redirect":
			http.Redirect(w, r, "/excluded-path", http.StatusFound)
		case "/excluded-path":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer primary.Close()

	engine := NewEngine(nil)
	scopedClient := engine.scopedClient(
		func(u string) bool { return strings.HasPrefix(u, primary.URL) },
		func(u string) bool { return strings.Contains(u, "/excluded-path") },
	)

	// 1. Out of scope redirect blocked
	_, err := scopedClient.Get(primary.URL + "/out-of-scope-redirect")
	if err == nil {
		t.Errorf("expected redirect to third-party to be blocked")
	}

	// 2. Redirect into excluded path blocked
	_, err = scopedClient.Get(primary.URL + "/excluded-redirect")
	if err == nil {
		t.Errorf("expected redirect into excluded path to be blocked")
	}
}

