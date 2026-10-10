package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// 1. Distinct identity cookies do not cross / leak into each other's cookie jars
func TestSessionManager_CookieIsolationBetweenIdentities(t *testing.T) {
	var mu sync.Mutex
	receivedCookies := make(map[string][]string)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		caller := r.Header.Get("X-Caller")
		for _, c := range r.Cookies() {
			receivedCookies[caller] = append(receivedCookies[caller], c.Name+"="+c.Value)
		}

		if r.URL.Path == "/login/alice" {
			http.SetCookie(w, &http.Cookie{
				Name:  "alice_session",
				Value: "token_for_alice_only",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/login/bob" {
			http.SetCookie(w, &http.Cookie{
				Name:  "bob_session",
				Value: "token_for_bob_only",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sm := NewSessionManager(5 * time.Second)

	clientAlice := sm.GetClientForIdentity("alice")
	clientBob := sm.GetClientForIdentity("bob")

	// Alice logs in and receives alice_session cookie
	reqAlice, _ := http.NewRequest(http.MethodGet, ts.URL+"/login/alice", nil)
	reqAlice.Header.Set("X-Caller", "alice")
	respAlice, err := clientAlice.Do(reqAlice)
	if err != nil {
		t.Fatalf("alice login failed: %v", err)
	}
	respAlice.Body.Close()

	// Bob logs in and receives bob_session cookie
	reqBob, _ := http.NewRequest(http.MethodGet, ts.URL+"/login/bob", nil)
	reqBob.Header.Set("X-Caller", "bob")
	respBob, err := clientBob.Do(reqBob)
	if err != nil {
		t.Fatalf("bob login failed: %v", err)
	}
	respBob.Body.Close()

	// Alice makes request to /api/check
	reqCheckAlice, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/check", nil)
	reqCheckAlice.Header.Set("X-Caller", "alice_check")
	respCheckAlice, _ := clientAlice.Do(reqCheckAlice)
	respCheckAlice.Body.Close()

	// Bob makes request to /api/check
	reqCheckBob, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/check", nil)
	reqCheckBob.Header.Set("X-Caller", "bob_check")
	respCheckBob, _ := clientBob.Do(reqCheckBob)
	respCheckBob.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	// Verify Alice sent ONLY alice_session
	aliceCookies := receivedCookies["alice_check"]
	for _, c := range aliceCookies {
		if strings.Contains(c, "bob_session") {
			t.Errorf("Cookie leak! Alice sent Bob's cookie: %s", c)
		}
	}
	if len(aliceCookies) == 0 || !strings.Contains(aliceCookies[0], "alice_session=token_for_alice_only") {
		t.Errorf("Alice did not send expected cookie: %v", aliceCookies)
	}

	// Verify Bob sent ONLY bob_session
	bobCookies := receivedCookies["bob_check"]
	for _, c := range bobCookies {
		if strings.Contains(c, "alice_session") {
			t.Errorf("Cookie leak! Bob sent Alice's cookie: %s", c)
		}
	}
	if len(bobCookies) == 0 || !strings.Contains(bobCookies[0], "bob_session=token_for_bob_only") {
		t.Errorf("Bob did not send expected cookie: %v", bobCookies)
	}
}

// 2. Preflight session check fails when credentials return 401/403 -> BLOCKED_INVALID_SESSION
func TestSessionManager_ExpiredSessionPreflightAndEngineBlocking(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if r.URL.Path == "/api/user/orders/101" {
			if auth == "Bearer valid-alice-token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"order_id": 101, "owner": "alice"}`))
				return
			}
			// Alice's token is expired or missing
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	// Configure policy where alice has an EXPIRED token
	policy := &AuthzPolicy{
		AssessmentRef:   "asm-test-expired",
		AllowWriteTests: true,
		Identities: map[string]TestIdentity{
			"alice": {
				Alias: "alice",
				Role:  "user",
				Headers: map[string]string{
					"Authorization": "Bearer expired-alice-token",
				},
			},
			"bob": {
				Alias: "bob",
				Role:  "user",
				Headers: map[string]string{
					"Authorization": "Bearer valid-bob-token",
				},
			},
		},
		Resources: map[string]TestResource{
			"order-101": {
				ID:         "order-101",
				Type:       "order",
				OwnerAlias: "alice",
			},
		},
		Endpoints: []EndpointRule{
			{
				Pattern:      "/api/user/orders/101",
				Method:       "GET",
				AllowedRoles: []string{"user"},
			},
		},
	}

	engine := NewEngine(&http.Client{Timeout: 5 * time.Second})

	// Preflight check direct verification
	sm := engine.SessionManager()
	preRes := sm.VerifyIdentitySession(
		context.Background(),
		"alice",
		policy.Identities["alice"],
		ts.URL+"/api/user/orders/101",
	)
	if preRes.Valid {
		t.Errorf("expected preflight for expired alice session to be invalid")
	}
	if preRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 status in preflight, got %d", preRes.StatusCode)
	}

	// Run full engine execution
	results, findings, summary, err := engine.Execute(
		context.Background(),
		ts.URL,
		policy,
		"asm-1",
		"exec-1",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)

	if err != nil {
		t.Fatalf("engine execution failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings when baseline identity has invalid session, got %d", len(findings))
	}

	var hasBlocked bool
	for _, r := range results {
		if r.VerificationState == StateBlockedInvalidSession {
			hasBlocked = true
			if !strings.Contains(r.EvidenceSummary, "session") {
				t.Errorf("expected session evidence summary, got %s", r.EvidenceSummary)
			}
		}
	}

	if !hasBlocked {
		t.Errorf("expected at least one result with StateBlockedInvalidSession")
	}

	if summary.BlockedCount == 0 {
		t.Errorf("expected summary.BlockedCount > 0, got %d", summary.BlockedCount)
	}
}

// 3. Environment variable credential injection
func TestSessionManager_InjectEnvCredentials(t *testing.T) {
	// Set test environment variables
	os.Setenv("FELIX_AUTH_TEST_USER_TOKEN", "super-secret-token-12345")
	os.Setenv("FELIX_AUTH_TEST_USER_COOKIE", "sid=test-session-cookie; role=tester")
	os.Setenv("FELIX_AUTH_TEST_USER_HEADER_X_API_KEY", "api-key-test-value")
	defer func() {
		os.Unsetenv("FELIX_AUTH_TEST_USER_TOKEN")
		os.Unsetenv("FELIX_AUTH_TEST_USER_COOKIE")
		os.Unsetenv("FELIX_AUTH_TEST_USER_HEADER_X_API_KEY")
	}()

	policy := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"test-user": {
				Alias: "test-user",
				Role:  "tester",
			},
		},
	}

	InjectEnvCredentials(policy)

	id := policy.Identities["test-user"]
	if id.Headers["Authorization"] != "Bearer super-secret-token-12345" {
		t.Errorf("expected Authorization header to be injected: %v", id.Headers["Authorization"])
	}
	if id.Headers["X-Api-Key"] != "api-key-test-value" {
		t.Errorf("expected X-Api-Key header to be injected: %v", id.Headers["X-Api-Key"])
	}
	if id.Cookies["sid"] != "test-session-cookie" {
		t.Errorf("expected sid cookie to be injected: %v", id.Cookies["sid"])
	}
	if id.Cookies["role"] != "tester" {
		t.Errorf("expected role cookie to be injected: %v", id.Cookies["role"])
	}
}

// 4. Comparative differential authorization (BOLA detection vs Denial)
func TestSessionManager_DifferentialAuthorizationBOLA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/documents/doc-100" {
			// Vulnerable endpoint: both alice and bob can read alice's document!
			if auth == "Bearer alice-token" || auth == "Bearer bob-token" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": "doc-100", "content": "confidential alice data"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/api/documents/doc-secure" {
			// Secure endpoint: only owner alice can read it
			if auth == "Bearer alice-token" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": "doc-secure", "content": "private data"}`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Forbidden"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	policy := &AuthzPolicy{
		AssessmentRef:   "asm-diff-test",
		AllowWriteTests: true,
		Identities: map[string]TestIdentity{
			"alice": {
				Alias:   "alice",
				Role:    "user",
				Headers: map[string]string{"Authorization": "Bearer alice-token"},
			},
			"bob": {
				Alias:   "bob",
				Role:    "user",
				Headers: map[string]string{"Authorization": "Bearer bob-token"},
			},
		},
		Resources: map[string]TestResource{
			"doc-100": {
				ID:         "doc-100",
				Type:       "document",
				OwnerAlias: "alice",
			},
			"doc-secure": {
				ID:         "doc-secure",
				Type:       "document",
				OwnerAlias: "alice",
			},
		},
		Endpoints: []EndpointRule{
			{
				Pattern:      "/api/documents/{id}",
				Method:       "GET",
				AllowedRoles: []string{"user"},
			},
		},
	}

	engine := NewEngine(&http.Client{Timeout: 5 * time.Second})

	results, findings, summary, err := engine.Execute(
		context.Background(),
		ts.URL,
		policy,
		"asm-diff",
		"exec-diff",
		func(u string) bool { return true },
		func(u string) bool { return false },
	)

	if err != nil {
		t.Fatalf("engine execution error: %v", err)
	}

	// Should verify BOLA on doc-100 (bob accessed alice's doc)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding for BOLA on doc-100, got %d", len(findings))
	}

	if summary.VerifiedCount != 1 {
		t.Errorf("expected 1 verified finding in summary, got %d", summary.VerifiedCount)
	}

	// Verify doc-secure was classified as NotVulnerable
	var foundSecureNotVuln bool
	for _, r := range results {
		if strings.Contains(r.Endpoint, "doc-secure") && r.PrimaryIdentity == "bob" {
			if r.VerificationState == StateNotVulnerable {
				foundSecureNotVuln = true
			}
		}
	}

	if !foundSecureNotVuln {
		t.Errorf("expected doc-secure check for bob to be classified as StateNotVulnerable")
	}
}
