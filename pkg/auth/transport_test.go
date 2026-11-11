package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// 1. Test: Unauthenticated requests contain no credentials.
func TestTransport_UnauthenticatedRequestsContainNoCredentials(t *testing.T) {
	var receivedAuth, receivedCookie, receivedCustom string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedCookie = r.Header.Get("Cookie")
		receivedCustom = r.Header.Get("X-Custom-Auth")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	// Register an authenticated User A to prove that unauthenticated requests do not leak User A credentials
	mgr.SetBearerToken(IdentityUserA, RoleVictim, "secret_user_a_token")

	client := mgr.ClientFor(IdentityUnauthenticated)
	resp, err := client.Get(server.URL + "/public")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedAuth != "" {
		t.Errorf("Expected empty Authorization header for Unauthenticated identity, got %q", receivedAuth)
	}
	if receivedCookie != "" {
		t.Errorf("Expected empty Cookie header for Unauthenticated identity, got %q", receivedCookie)
	}
	if receivedCustom != "" {
		t.Errorf("Expected empty custom auth header for Unauthenticated identity, got %q", receivedCustom)
	}
}

// 2. Test: User A requests carry only User A credentials.
func TestTransport_UserARequestsCarryOnlyUserACredentials(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, "token_user_a_123")
	mgr.SetBearerToken(IdentityUserB, RoleAttacker, "token_user_b_456")
	mgr.SetBearerToken(IdentityAdmin, RoleAdmin, "token_admin_789")

	client := mgr.ClientFor(IdentityUserA)
	resp, err := client.Get(server.URL + "/user_a_profile")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	expected := "Bearer token_user_a_123"
	if receivedAuth != expected {
		t.Errorf("Expected Authorization header %q, got %q", expected, receivedAuth)
	}
}

// 3. Test: User B requests carry only User B credentials.
func TestTransport_UserBRequestsCarryOnlyUserBCredentials(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, "token_user_a_123")
	mgr.SetBearerToken(IdentityUserB, RoleAttacker, "token_user_b_456")

	client := mgr.ClientFor(IdentityUserB)
	resp, err := client.Get(server.URL + "/user_b_profile")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	expected := "Bearer token_user_b_456"
	if receivedAuth != expected {
		t.Errorf("Expected Authorization header %q, got %q", expected, receivedAuth)
	}
}

// 4. Test: Admin requests carry only Admin credentials.
func TestTransport_AdminRequestsCarryOnlyAdminCredentials(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, "token_user_a_123")
	mgr.SetBearerToken(IdentityAdmin, RoleAdmin, "token_admin_supersecret")

	client := mgr.ClientFor(IdentityAdmin)
	resp, err := client.Get(server.URL + "/admin_dashboard")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	expected := "Bearer token_admin_supersecret"
	if receivedAuth != expected {
		t.Errorf("Expected Authorization header %q, got %q", expected, receivedAuth)
	}
}

// 5. Test: Concurrent requests never mix identities.
func TestTransport_ConcurrentRequestsNeverMixIdentities(t *testing.T) {
	tokA := "tok_alpha_user_a"
	tokB := "tok_beta_user_b"
	tokAdmin := "tok_gamma_admin"

	var mismatchCount int64
	var mu sync.Mutex
	logMismatch := func(endpoint, expected, actual string) {
		mu.Lock()
		defer mu.Unlock()
		mismatchCount++
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		path := r.URL.Path

		switch path {
		case "/a":
			if authHdr != "Bearer "+tokA {
				logMismatch(path, "Bearer "+tokA, authHdr)
			}
		case "/b":
			if authHdr != "Bearer "+tokB {
				logMismatch(path, "Bearer "+tokB, authHdr)
			}
		case "/admin":
			if authHdr != "Bearer "+tokAdmin {
				logMismatch(path, "Bearer "+tokAdmin, authHdr)
			}
		case "/anon":
			if authHdr != "" {
				logMismatch(path, "<empty>", authHdr)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, tokA)
	mgr.SetBearerToken(IdentityUserB, RoleAttacker, tokB)
	mgr.SetBearerToken(IdentityAdmin, RoleAdmin, tokAdmin)

	clientA := mgr.ClientFor(IdentityUserA)
	clientB := mgr.ClientFor(IdentityUserB)
	clientAdmin := mgr.ClientFor(IdentityAdmin)
	clientAnon := mgr.ClientFor(IdentityUnauthenticated)

	var wg sync.WaitGroup
	workers := 25 // 25 of each = 100 concurrent requests

	for i := 0; i < workers; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			resp, err := clientA.Get(server.URL + "/a")
			if err == nil {
				resp.Body.Close()
			}
		}()

		go func() {
			defer wg.Done()
			resp, err := clientB.Get(server.URL + "/b")
			if err == nil {
				resp.Body.Close()
			}
		}()

		go func() {
			defer wg.Done()
			resp, err := clientAdmin.Get(server.URL + "/admin")
			if err == nil {
				resp.Body.Close()
			}
		}()

		go func() {
			defer wg.Done()
			resp, err := clientAnon.Get(server.URL + "/anon")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()

	if mismatchCount > 0 {
		t.Fatalf("Concurrency failure: observed %d identity mismatches/leaks across concurrent requests", mismatchCount)
	}
}

// 6. Test: Bearer authentication survives internal same-origin requests.
func TestTransport_BearerAuthSurvivesInternalSameOriginRequests(t *testing.T) {
	var finalAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		finalAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, "persisting_bearer_tok")

	client := mgr.ClientFor(IdentityUserA)
	resp, err := client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	expected := "Bearer persisting_bearer_tok"
	if finalAuth != expected {
		t.Errorf("Bearer token did not survive internal same-origin redirect: expected %q, got %q", expected, finalAuth)
	}
}

// 7. Test: Cookie authentication respects domain and path scope.
func TestTransport_CookieAuthRespectsDomainAndPathScope(t *testing.T) {
	var receivedCookieOnAPI string
	var receivedCookieOnPublic string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/data" {
			receivedCookieOnAPI = r.Header.Get("Cookie")
		} else if r.URL.Path == "/public/data" {
			receivedCookieOnPublic = r.Header.Get("Cookie")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	// Set cookie specifically scoped to /api
	err = mgr.SetCookie(IdentityUserA, RoleVictim, "session_id=api_secret_cookie; Path=/api")
	if err != nil {
		t.Fatalf("Failed to set cookie: %v", err)
	}

	client := mgr.ClientFor(IdentityUserA)

	// Probe path inside cookie scope
	respAPI, err := client.Get(server.URL + "/api/data")
	if err != nil {
		t.Fatalf("API request failed: %v", err)
	}
	respAPI.Body.Close()

	// Probe path outside cookie scope
	respPublic, err := client.Get(server.URL + "/public/data")
	if err != nil {
		t.Fatalf("Public request failed: %v", err)
	}
	respPublic.Body.Close()

	if !strings.Contains(receivedCookieOnAPI, "session_id=api_secret_cookie") {
		t.Errorf("Expected cookie on /api/data, got %q", receivedCookieOnAPI)
	}
	if strings.Contains(receivedCookieOnPublic, "session_id=api_secret_cookie") {
		t.Errorf("Cookie leaked outside permitted path to /public/data: %q", receivedCookieOnPublic)
	}
}

// 8. Test: External-origin redirects do not receive credentials.
func TestTransport_ExternalOriginRedirectsDoNotReceiveCredentials(t *testing.T) {
	var externalReceivedAuth, externalReceivedCookie string

	// External server (representing a malicious or foreign third-party origin)
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalReceivedAuth = r.Header.Get("Authorization")
		externalReceivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer externalServer.Close()

	// Target server that redirects to external server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalServer.URL+"/capture", http.StatusFound)
	}))
	defer targetServer.Close()

	// We allow scope to include both URLs for this test to observe the transport's origin-confinement behavior
	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     targetServer.URL,
		AllowLoopback: true,
		ScopeAllowed: func(u string) bool {
			return true // Scope allows the redirect to proceed, but transport must strip auth
		},
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	mgr.SetBearerToken(IdentityUserA, RoleVictim, "confidential_token")
	_ = mgr.SetCookie(IdentityUserA, RoleVictim, "session=secret_session; Path=/")

	client := mgr.ClientFor(IdentityUserA)
	resp, err := client.Get(targetServer.URL + "/trigger_redirect")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if externalReceivedAuth != "" {
		t.Errorf("CRITICAL LEAK: External origin received Authorization header: %q", externalReceivedAuth)
	}
	if externalReceivedCookie != "" {
		t.Errorf("CRITICAL LEAK: External origin received Cookie header: %q", externalReceivedCookie)
	}
}

// 9. Test: Redirect handling cannot bypass scope enforcement.
func TestTransport_RedirectHandlingCannotBypassScopeEnforcement(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://unauthorized-attacker.example/exfil", http.StatusFound)
	}))
	defer targetServer.Close()

	targetHost := strings.TrimPrefix(targetServer.URL, "http://")

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     targetServer.URL,
		AllowLoopback: true,
		ScopeAllowed: func(u string) bool {
			parsed, err := url.Parse(u)
			if err != nil {
				return false
			}
			return parsed.Host == targetHost // strictly allow only target host
		},
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	client := mgr.ClientFor(IdentityUserA)
	_, err = client.Get(targetServer.URL + "/redirect_out_of_scope")
	if err == nil {
		t.Fatalf("Expected redirect to out-of-scope host to be blocked, but request succeeded")
	}

	if !strings.Contains(err.Error(), "out-of-scope") && !strings.Contains(err.Error(), "blocked") {
		t.Errorf("Expected out-of-scope redirect refusal error, got: %v", err)
	}
}

// 10. Test: Expired or invalid credentials produce accurate outcomes.
func TestTransport_ExpiredOrInvalidCredentialsProduceAccurateOutcomes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "Bearer valid_token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_or_expired_token"}`))
	}))
	defer server.Close()

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     server.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	// 1. Verify invalid token
	mgr.SetBearerToken(IdentityUserA, RoleVictim, "bad_or_expired_token")
	verRes, err := mgr.VerifyIdentity(context.Background(), IdentityUserA, "/auth_check")
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	if verRes.Verified {
		t.Errorf("Expected invalid token to fail verification, but was marked verified")
	}
	if verRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected HTTP 401 Unauthorized, got %d", verRes.StatusCode)
	}
	if verRes.State != AuthStateExpiredConfirmed {
		t.Errorf("Expected AuthStateExpiredConfirmed, got %s", verRes.State)
	}

	// 2. Verify valid token
	mgr.SetBearerToken(IdentityUserA, RoleVictim, "valid_token")
	verResValid, err := mgr.VerifyIdentity(context.Background(), IdentityUserA, "/auth_check")
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if !verResValid.Verified {
		t.Errorf("Expected valid token to pass verification, failed: %s", verResValid.FailureReason)
	}
	if verResValid.State != AuthStateConfirmed {
		t.Errorf("Expected AuthStateConfirmed, got %s", verResValid.State)
	}
}

// 11. Test: Credentials never appear in logs or reports.
func TestTransport_CredentialsNeverAppearInLogsOrReports(t *testing.T) {
	rawSecretToken := "super_secret_jwt_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y9GenericToken"
	rawCookie := "session_id=ultra_private_session_token_xyz"

	// 1. Verify RedactAuthHeader
	redactedHdr := RedactAuthHeader("Authorization", "Bearer "+rawSecretToken)
	if strings.Contains(redactedHdr, rawSecretToken) {
		t.Errorf("RedactAuthHeader leaked raw Authorization token: %s", redactedHdr)
	}

	redactedCookie := RedactAuthHeader("Cookie", rawCookie)
	if strings.Contains(redactedCookie, "ultra_private_session_token_xyz") {
		t.Errorf("RedactAuthHeader leaked raw session cookie: %s", redactedCookie)
	}

	// 2. Verify IdentityCredential JSON marshaling hides secrets
	cred := IdentityCredential{
		ID:          IdentityUserA,
		Role:        RoleVictim,
		AuthMethod:  AuthMethodBearer,
		Username:    "alice",
		BearerToken: rawSecretToken,
		HeaderName:  "X-API-Key",
		HeaderValue: "raw_secret_api_key",
		Cookies: []*http.Cookie{
			{Name: "session", Value: "secret_value"},
		},
	}

	jsonBytes, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Failed to marshal IdentityCredential: %v", err)
	}
	jsonStr := string(jsonBytes)

	if strings.Contains(jsonStr, rawSecretToken) {
		t.Errorf("IdentityCredential JSON leaked raw bearer token: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "raw_secret_api_key") {
		t.Errorf("IdentityCredential JSON leaked raw API key: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "secret_value") {
		t.Errorf("IdentityCredential JSON leaked cookie secret: %s", jsonStr)
	}

	// 3. Verify IdentityCredentialSummary
	summary := cred.Summary()
	sumBytes, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal summary: %v", err)
	}
	sumStr := string(sumBytes)
	if strings.Contains(sumStr, rawSecretToken) {
		t.Errorf("IdentityCredentialSummary leaked token: %s", sumStr)
	}
}

// 12. Test: Existing safety and SSRF protections continue to work.
func TestTransport_ExistingSafetyAndSSRFProtectionsWork(t *testing.T) {
	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL:     "http://169.254.169.254", // Cloud metadata IP
		AllowLoopback: false,
		AllowPrivate:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create IdentityManager: %v", err)
	}

	client := mgr.ClientFor(IdentityUnauthenticated)

	_, err = client.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatalf("Expected SSRF protection to block connection to 169.254.169.254, but request succeeded")
	}

	if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "prohibited") && !strings.Contains(err.Error(), "refusal") {
		t.Errorf("Expected SSRF refusal error message, got: %v", err)
	}
}
