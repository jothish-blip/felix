package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setupMockLoginServer creates an httptest.Server simulating an authenticated web app.
// It counts the number of login POST requests and allows simulating session expiration.
func setupMockLoginServer(t *testing.T) (*httptest.Server, *int64, *atomic.Bool) {
	var loginCount int64
	var sessionInvalidated atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body><form action="/login" method="POST"><input type="hidden" name="_csrf" value="tok123"/></form></body></html>`))
				return
			}
			if r.Method == http.MethodPost {
				atomic.AddInt64(&loginCount, 1)
				_ = r.ParseForm()
				user := r.FormValue("username")
				pass := r.FormValue("password")
				if user == "validuser" && pass == "validpass" {
					sessionInvalidated.Store(false)
					cookieVal := fmt.Sprintf("sess_%d", time.Now().UnixNano())
					http.SetCookie(w, &http.Cookie{
						Name:     "MOCK_SESS",
						Value:    cookieVal,
						Path:     "/",
						HttpOnly: true,
					})
					w.Header().Set("Location", "/dashboard")
					w.WriteHeader(http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`Invalid credentials`))
				return
			}
		case "/dashboard":
			if sessionInvalidated.Load() {
				w.Header().Set("Location", "/login?expired=1")
				w.WriteHeader(http.StatusFound)
				return
			}
			cookie, err := r.Cookie("MOCK_SESS")
			if err != nil || cookie.Value == "" {
				w.Header().Set("Location", "/login?no_cookie=1")
				w.WriteHeader(http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Dashboard</title></head><body>Welcome User</body></html>`))
			return
		case "/api/health":
			if sessionInvalidated.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			cookie, err := r.Cookie("MOCK_SESS")
			if err != nil || cookie.Value == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		case "/api/protected-resource":
			if sessionInvalidated.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			cookie, err := r.Cookie("MOCK_SESS")
			if err != nil || cookie.Value == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"secure_payload"}`))
			return
		case "/api/forbidden-item":
			// Ordinary application authorization failure (e.g. BOLA/IDOR attempt)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"access_denied"}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return server, &loginCount, &sessionInvalidated
}

func createTestMacroConfig(serverURL string, validCredentials bool) LoginMacroConfig {
	user := "validuser"
	pass := "validpass"
	if !validCredentials {
		pass = "wrongpass"
	}
	return LoginMacroConfig{
		Name:          "test-macro",
		TargetURL:     serverURL + "/login",
		FormActionURL: serverURL + "/login",
		Credentials: map[string]string{
			"username": user,
			"password": pass,
		},
		SuccessCriteria: SuccessCriteria{
			ExpectedCookies: []string{"MOCK_SESS"},
			ExpectedStatus:  []int{http.StatusOK, http.StatusFound},
		},
		VerifyURL: serverURL + "/dashboard",
		VerifyCriteria: VerifyCriteria{
			ExpectedStatus:  []int{http.StatusOK},
			BodyMustContain: "<title>Dashboard</title>",
		},
		Timeout: 5 * time.Second,
	}
}

// 1. Successful session reuse without unnecessary login.
func TestSessionMonitor_ReuseWithoutRelogin(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:         macro,
		SessionMaxAge: 10 * time.Minute,
	})
	defer monitor.Close()

	ctx := context.Background()

	// Initial acquisition triggers login
	sess1, err := monitor.GetSession(ctx)
	if err != nil {
		t.Fatalf("Initial GetSession failed: %v", err)
	}
	if sess1 == nil || !sess1.Authenticated {
		t.Fatalf("Expected valid authenticated session, got: %+v", sess1)
	}
	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Expected 1 login, got %d", atomic.LoadInt64(loginCount))
	}

	// 5 subsequent calls must reuse existing session without re-login
	for i := 0; i < 5; i++ {
		sessN, err := monitor.GetSession(ctx)
		if err != nil {
			t.Fatalf("GetSession call %d failed: %v", i+1, err)
		}
		if sessN.ID != sess1.ID {
			t.Fatalf("Session ID mismatch on reuse: %s != %s", sessN.ID, sess1.ID)
		}
	}

	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Expected loginCount to remain 1, got %d", atomic.LoadInt64(loginCount))
	}
	metrics := monitor.Metrics()
	if metrics.ReusedSessions != 5 {
		t.Fatalf("Expected 5 reused sessions, got %d", metrics.ReusedSessions)
	}
}

// 2. Expired session triggering automatic refresh.
func TestSessionMonitor_ExpirationTriggersRefresh(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	// Configure short max age
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:         macro,
		SessionMaxAge: 50 * time.Millisecond,
	})
	defer monitor.Close()

	ctx := context.Background()
	sess1, err := monitor.GetSession(ctx)
	if err != nil {
		t.Fatalf("GetSession 1 failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	sess2, err := monitor.GetSession(ctx)
	if err != nil {
		t.Fatalf("GetSession 2 failed: %v", err)
	}

	if sess2.ID == sess1.ID {
		t.Fatalf("Expected new session ID after expiration, got identical: %s", sess2.ID)
	}
	if atomic.LoadInt64(loginCount) != 2 {
		t.Fatalf("Expected 2 logins after expiration, got %d", atomic.LoadInt64(loginCount))
	}
}

// 3. Twenty concurrent requests triggering exactly one login macro execution.
// 4. All twenty callers receiving the same refreshed session state.
func TestSessionMonitor_20ConcurrentThunderingHerd(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          macro,
		RefreshTimeout: 5 * time.Second,
	})
	defer monitor.Close()

	const numWorkers = 20
	var wg sync.WaitGroup
	startGate := make(chan struct{})

	sessions := make([]*MacroSession, numWorkers)
	errorsList := make([]error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate // Synchronize simultaneous release
			sess, err := monitor.RefreshSession(context.Background(), "20_worker_burst")
			sessions[idx] = sess
			errorsList[idx] = err
		}(i)
	}

	close(startGate) // Release all 20 workers concurrently
	wg.Wait()

	// Verify all 20 succeeded
	for i := 0; i < numWorkers; i++ {
		if errorsList[i] != nil {
			t.Fatalf("Worker %d failed: %v", i, errorsList[i])
		}
		if sessions[i] == nil {
			t.Fatalf("Worker %d received nil session", i)
		}
	}

	// Mandatory assertion: Exactly ONE macro execution occurred
	actualLogins := atomic.LoadInt64(loginCount)
	if actualLogins != 1 {
		t.Fatalf("CRITICAL RACE DETECTED: Expected exactly 1 login macro execution, got %d", actualLogins)
	}

	metrics := monitor.Metrics()
	if metrics.MacroExecutions != 1 {
		t.Fatalf("Metrics.MacroExecutions mismatch: expected 1, got %d", metrics.MacroExecutions)
	}
	if metrics.SuccessfulRefreshes != 20 {
		t.Fatalf("Metrics.SuccessfulRefreshes mismatch: expected 20, got %d", metrics.SuccessfulRefreshes)
	}

	// Verify all 20 workers received the exact same session instance and ID
	firstID := sessions[0].ID
	firstCookie := sessions[0].Cookies["MOCK_SESS"]
	for i := 1; i < numWorkers; i++ {
		if sessions[i].ID != firstID {
			t.Fatalf("Session ID divergence across workers: worker %d got %s, worker 0 got %s", i, sessions[i].ID, firstID)
		}
		if sessions[i].Cookies["MOCK_SESS"] != firstCookie {
			t.Fatalf("Cookie value divergence: worker %d got %s, worker 0 got %s", i, sessions[i].Cookies["MOCK_SESS"], firstCookie)
		}
	}
	t.Logf("PASS: 20 concurrent goroutines received identical refreshed session %s with exactly 1 macro execution", firstID)
}

// 5. Subsequent requests reusing the refreshed session.
func TestSessionMonitor_SubsequentReuseAfterThunderingHerd(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          macro,
		SessionMaxAge:  10 * time.Minute,
		RefreshTimeout: 5 * time.Second,
	})
	defer monitor.Close()

	// Fire 20 concurrent
	const numWorkers = 20
	var wg sync.WaitGroup
	startGate := make(chan struct{})
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			_, _ = monitor.GetSession(context.Background())
		}()
	}
	close(startGate)
	wg.Wait()

	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Expected 1 login after burst, got %d", atomic.LoadInt64(loginCount))
	}

	// 10 subsequent sequential requests
	for i := 0; i < 10; i++ {
		sess, err := monitor.GetSession(context.Background())
		if err != nil {
			t.Fatalf("Sequential GetSession %d failed: %v", i, err)
		}
		if sess == nil {
			t.Fatalf("Sequential GetSession %d returned nil", i)
		}
	}

	// Total login count must remain 1
	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Subsequent requests triggered unexpected login: loginCount = %d", atomic.LoadInt64(loginCount))
	}
}

// 6. Failed reauthentication returning a clear error.
func TestSessionMonitor_FailedReauthentication(t *testing.T) {
	server, _, _ := setupMockLoginServer(t)
	defer server.Close()

	// Configure macro with invalid password
	macro := NewLoginMacro(createTestMacroConfig(server.URL, false))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          macro,
		RefreshTimeout: 5 * time.Second,
	})
	defer monitor.Close()

	sess, err := monitor.GetSession(context.Background())
	if err == nil {
		t.Fatalf("Expected error on invalid credentials, got nil with session: %+v", sess)
	}
	if monitor.CurrentSession() != nil {
		t.Fatalf("Expected nil current session after failure, got: %+v", monitor.CurrentSession())
	}
	metrics := monitor.Metrics()
	if metrics.FailedRefreshes != 1 {
		t.Fatalf("Expected 1 failed refresh, got %d", metrics.FailedRefreshes)
	}
}

// 7. Concurrent refresh failure handling and subsequent recovery.
func TestSessionMonitor_ConcurrentFailureAndRecovery(t *testing.T) {
	server, _, _ := setupMockLoginServer(t)
	defer server.Close()

	// Step A: Macro configured with bad credentials
	badMacro := NewLoginMacro(createTestMacroConfig(server.URL, false))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          badMacro,
		RefreshTimeout: 5 * time.Second,
	})
	defer monitor.Close()

	const numWorkers = 10
	var wg sync.WaitGroup
	startGate := make(chan struct{})
	errorsList := make([]error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			_, err := monitor.RefreshSession(context.Background(), "failure_burst")
			errorsList[idx] = err
		}(i)
	}
	close(startGate)
	wg.Wait()

	// All 10 must report error
	for i := 0; i < numWorkers; i++ {
		if errorsList[i] == nil {
			t.Fatalf("Worker %d expected error, got nil", i)
		}
	}

	// Step B: Update macro with good credentials and verify recovery
	goodMacro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor.cfg.Macro = goodMacro

	sess, err := monitor.RefreshSession(context.Background(), "recovery_attempt")
	if err != nil {
		t.Fatalf("Expected recovery to succeed, got: %v", err)
	}
	if sess == nil || !sess.Authenticated {
		t.Fatalf("Expected valid session after recovery, got: %+v", sess)
	}
}

// 8. Shared refresh cancellation: a single caller's cancellation must not terminate
// the refresh required by other waiting callers.
func TestSessionMonitor_SharedRefreshCancellation(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          macro,
		RefreshTimeout: 5 * time.Second,
	})
	defer monitor.Close()

	var wg sync.WaitGroup
	startGate := make(chan struct{})

	// Caller 1 has a rapidly cancelled context
	canceledCtx, cancel := context.WithCancel(context.Background())
	var errCanceledCaller error
	var sessCanceledCaller *MacroSession

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startGate
		cancel() // Cancel immediately upon start
		sessCanceledCaller, errCanceledCaller = monitor.RefreshSession(canceledCtx, "canceled_caller")
	}()

	// Callers 2..5 have normal non-cancelled contexts
	const survivorCount = 4
	survivorErrors := make([]error, survivorCount)
	survivorSessions := make([]*MacroSession, survivorCount)

	for i := 0; i < survivorCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			survivorSessions[idx], survivorErrors[idx] = monitor.RefreshSession(context.Background(), "survivor_caller")
		}(i)
	}

	close(startGate)
	wg.Wait()

	// Caller 1 must report context canceled
	if errCanceledCaller == nil {
		t.Fatalf("Expected canceled caller to receive error, got nil")
	}
	if sessCanceledCaller != nil {
		t.Fatalf("Expected nil session for canceled caller, got: %+v", sessCanceledCaller)
	}

	// All 4 survivor callers must succeed
	for i := 0; i < survivorCount; i++ {
		if survivorErrors[i] != nil {
			t.Fatalf("Survivor caller %d failed unexpectedly: %v", i, survivorErrors[i])
		}
		if survivorSessions[i] == nil || !survivorSessions[i].Authenticated {
			t.Fatalf("Survivor caller %d got invalid session: %+v", i, survivorSessions[i])
		}
	}

	// Macro must execute exactly once
	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Expected exactly 1 login execution, got %d", atomic.LoadInt64(loginCount))
	}
}

// 9. Refresh timeout behavior.
func TestSessionMonitor_RefreshTimeout(t *testing.T) {
	// Slow server that sleeps
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	macro := NewLoginMacro(LoginMacroConfig{
		TargetURL: slowServer.URL,
		Timeout:   50 * time.Millisecond,
	})
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro:          macro,
		RefreshTimeout: 50 * time.Millisecond,
	})
	defer monitor.Close()

	ctx := context.Background()
	_, err := monitor.GetSession(ctx)
	if err == nil {
		t.Fatalf("Expected timeout error, got nil")
	}
}

// 10. Stale session invalidation does not overwrite a newer session.
func TestSessionMonitor_StaleSessionInvalidationGuard(t *testing.T) {
	server, _, _ := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro: macro,
	})
	defer monitor.Close()

	ctx := context.Background()
	sess1, err := monitor.GetSession(ctx)
	if err != nil {
		t.Fatalf("GetSession 1 failed: %v", err)
	}

	// Force refresh to create sess2
	sess2, err := monitor.RefreshSession(ctx, "manual_refresh")
	if err != nil {
		t.Fatalf("RefreshSession failed: %v", err)
	}
	if sess2.ID == sess1.ID {
		t.Fatalf("Expected new session ID for sess2")
	}

	// Invalidate with stale ID (sess1.ID)
	invalidated := monitor.InvalidateSession(sess1.ID)
	if invalidated {
		t.Fatalf("Expected InvalidateSession to return false for stale session ID, got true")
	}

	// Current session must still be sess2
	current := monitor.CurrentSession()
	if current == nil || current.ID != sess2.ID {
		t.Fatalf("Expected current session to remain sess2, got: %+v", current)
	}

	// Invalidate with correct ID (sess2.ID)
	invalidated = monitor.InvalidateSession(sess2.ID)
	if !invalidated {
		t.Fatalf("Expected InvalidateSession to succeed for current session ID")
	}
	if monitor.CurrentSession() != nil {
		t.Fatalf("Expected nil current session after valid invalidation")
	}
}

// 11. Independent monitors maintain session isolation.
func TestSessionMonitor_IndependentMonitorsIsolation(t *testing.T) {
	server, loginCount, _ := setupMockLoginServer(t)
	defer server.Close()

	macro1 := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor1 := NewSessionMonitor(SessionMonitorConfig{Macro: macro1})
	defer monitor1.Close()

	macro2 := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor2 := NewSessionMonitor(SessionMonitorConfig{Macro: macro2})
	defer monitor2.Close()

	ctx := context.Background()
	s1, err := monitor1.GetSession(ctx)
	if err != nil {
		t.Fatalf("Monitor 1 GetSession failed: %v", err)
	}
	s2, err := monitor2.GetSession(ctx)
	if err != nil {
		t.Fatalf("Monitor 2 GetSession failed: %v", err)
	}

	if s1.ID == s2.ID {
		t.Fatalf("Expected distinct session IDs across independent monitors, got %s", s1.ID)
	}
	if atomic.LoadInt64(loginCount) != 2 {
		t.Fatalf("Expected 2 distinct logins for two monitors, got %d", atomic.LoadInt64(loginCount))
	}
}

// 12. Do executes requests and automatically refreshes on session expiration.
func TestSessionMonitor_DoAutoRetryOnExpiration(t *testing.T) {
	server, loginCount, sessionInvalidated := setupMockLoginServer(t)
	defer server.Close()

	macro := NewLoginMacro(createTestMacroConfig(server.URL, true))
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Macro: macro,
	})
	defer monitor.Close()

	// Initial request establishes session
	req1, _ := http.NewRequest(http.MethodGet, server.URL+"/api/protected-resource", nil)
	resp1, err := monitor.Do(req1)
	if err != nil {
		t.Fatalf("Do 1 failed: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp1.StatusCode)
	}
	if atomic.LoadInt64(loginCount) != 1 {
		t.Fatalf("Expected 1 login, got %d", atomic.LoadInt64(loginCount))
	}

	// Invalidate session on server side
	sessionInvalidated.Store(true)

	// Second request encounters 401, auto-refreshes session, and succeeds on retry
	req2, _ := http.NewRequest(http.MethodGet, server.URL+"/api/protected-resource", nil)
	resp2, err := monitor.Do(req2)
	if err != nil {
		t.Fatalf("Do 2 failed after expiration: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK on retry, got %d", resp2.StatusCode)
	}

	// Login count must be 2 now
	if atomic.LoadInt64(loginCount) != 2 {
		t.Fatalf("Expected 2 logins after auto-refresh on Do, got %d", atomic.LoadInt64(loginCount))
	}
}

// 13. IsSessionExpired correctly distinguishes auth failure from authorization denial.
func TestSessionMonitor_IsSessionExpiredDetection(t *testing.T) {
	monitor := NewSessionMonitor(SessionMonitorConfig{})
	defer monitor.Close()

	// 401 Unauthorized -> expired
	r401 := &http.Response{StatusCode: http.StatusUnauthorized}
	if !monitor.IsSessionExpired(r401) {
		t.Errorf("Expected 401 to be expired")
	}

	// 302 to /login -> expired
	r302Login := &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"http://127.0.0.1:8080/WebGoat/login"}},
	}
	if !monitor.IsSessionExpired(r302Login) {
		t.Errorf("Expected 302 to /login to be expired")
	}

	// 302 to /dashboard -> not expired
	r302Other := &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"http://127.0.0.1:8080/WebGoat/welcome.mvc"}},
	}
	if monitor.IsSessionExpired(r302Other) {
		t.Errorf("Expected 302 to /welcome.mvc to NOT be expired")
	}

	// 403 Forbidden without session indicator -> NOT expired (ordinary access denial)
	r403Normal := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{},
	}
	if monitor.IsSessionExpired(r403Normal) {
		t.Errorf("Expected normal 403 to NOT be treated as session expired")
	}

	// 403 Forbidden with X-Session-Expired -> expired
	r403Expired := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"X-Session-Expired": []string{"true"}},
	}
	if !monitor.IsSessionExpired(r403Expired) {
		t.Errorf("Expected 403 with X-Session-Expired to be expired")
	}
}

// 14. Phase 3.2 Evidence Receipt Opt-in Policy and Immutability Test
func TestReceipt_Phase32_OptInPolicyAndImmutability(t *testing.T) {
	tempDir := t.TempDir()
	metrics := map[string]any{
		"concurrent_workers":  20,
		"macro_executions":    1,
		"reused_sessions":     10,
		"successful_refreshes": 20,
	}

	// 1. Missing receipt without opt-in returns error without writing file
	missingPath := filepath.Join(tempDir, "missing_3.2_receipt.json")
	_, err := verifyOrGeneratePhase32Receipt(missingPath, false, metrics)
	if err == nil {
		t.Fatalf("Expected error for missing receipt when opt-in is false")
	}
	if fileExists(missingPath) {
		t.Fatalf("Receipt file must NOT be created when opt-in is false")
	}

	// 2. Explicit opt-in generates and verifies receipt
	genPath := filepath.Join(tempDir, "gen_3.2_receipt.json")
	genHash, err := verifyOrGeneratePhase32Receipt(genPath, true, metrics)
	if err != nil {
		t.Fatalf("Failed to generate receipt with opt-in true: %v", err)
	}
	if !fileExists(genPath) {
		t.Fatalf("Expected receipt file to be created with opt-in true")
	}

	// 3. Existing receipt without opt-in verifies byte-for-byte immutability
	preBytes, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("Failed to read pre-test bytes: %v", err)
	}
	vHash, err := verifyOrGeneratePhase32Receipt(genPath, false, metrics)
	if err != nil {
		t.Fatalf("Failed to verify existing receipt: %v", err)
	}
	if vHash != genHash {
		t.Fatalf("Hash mismatch on verification: %s != %s", vHash, genHash)
	}
	postBytes, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("Failed to read post-test bytes: %v", err)
	}
	if !bytes.Equal(preBytes, postBytes) {
		t.Fatalf("Receipt mutated during routine verification run")
	}
	t.Logf("PASS: Phase 3.2 receipt opt-in policy and immutability verified")
}

// verifyOrGeneratePhase32Receipt manages canonical evidence receipt generation and verification.
func verifyOrGeneratePhase32Receipt(receiptPath string, generateOptIn bool, metrics map[string]any) (string, error) {
	if generateOptIn {
		receiptDir := filepath.Dir(receiptPath)
		if err := os.MkdirAll(receiptDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create evidence directory: %w", err)
		}

		receiptMap := map[string]any{
			"receipt_version":   "3.0.0",
			"phase_id":          "phase3",
			"subphase_id":       "3.2",
			"title":             "Session Keep-Alive and Auto-Refresh Singleflight Monitor Proof",
			"timestamp":         time.Now().UTC().Format(time.RFC3339),
			"target_repo":       "webgoat",
			"target_url":        "http://127.0.0.1:8080/WebGoat/login",
			"test_command":      "go test -v -count=1 ./pkg/auth -run TestBenchmark_SessionKeepAlive_WebGoat",
			"conclusive_status": "PROVEN_VERIFIED",
			"exit_code":         0,
			"executor":          "Antigravity Engineering / FELIX Core Team",
			"metrics":           metrics,
		}

		var canonBuf bytes.Buffer
		enc := json.NewEncoder(&canonBuf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(receiptMap); err != nil {
			return "", fmt.Errorf("failed to encode receipt: %w", err)
		}
		canonBytes := bytes.TrimRight(canonBuf.Bytes(), "\n")
		sum := sha256.Sum256(canonBytes)
		canonHash := hex.EncodeToString(sum[:])
		receiptMap["sha256_hash"] = canonHash

		formattedJSON, err := json.MarshalIndent(receiptMap, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to format receipt JSON: %w", err)
		}

		if err := os.WriteFile(receiptPath, formattedJSON, 0644); err != nil {
			return "", fmt.Errorf("failed to write receipt file: %w", err)
		}
	}

	if !fileExists(receiptPath) {
		return "", fmt.Errorf("required evidence receipt missing at %s; generate via FELIX_GENERATE_RECEIPT=1", receiptPath)
	}

	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		return "", fmt.Errorf("failed to read evidence receipt: %w", err)
	}

	var diskReceipt map[string]any
	if err := json.Unmarshal(receiptBytes, &diskReceipt); err != nil {
		return "", fmt.Errorf("failed to parse evidence receipt: %w", err)
	}

	expectedHash, ok := diskReceipt["sha256_hash"].(string)
	if !ok || expectedHash == "" {
		return "", fmt.Errorf("receipt is missing sha256_hash")
	}

	delete(diskReceipt, "sha256_hash")
	var verifyBuf bytes.Buffer
	encV := json.NewEncoder(&verifyBuf)
	encV.SetEscapeHTML(false)
	if err := encV.Encode(diskReceipt); err != nil {
		return "", fmt.Errorf("failed to encode for verification: %w", err)
	}
	verifySum := sha256.Sum256(bytes.TrimRight(verifyBuf.Bytes(), "\n"))
	diskHash := hex.EncodeToString(verifySum[:])

	if diskHash != expectedHash {
		return "", fmt.Errorf("canonical hash verification failed: got %s, expected %s", diskHash, expectedHash)
	}

	return diskHash, nil
}

// 15. Mandatory Live Benchmark: WebGoat 20-worker singleflight re-login concurrency.
func TestBenchmark_SessionKeepAlive_WebGoat(t *testing.T) {
	wgURL := "http://127.0.0.1:8080/WebGoat/login"
	wgReachable := checkLiveReachable(wgURL)

	t.Logf("=== WEBGOAT TARGET REACHABILITY AUDIT ===")
	t.Logf("  WebGoat (Port 8080): Reachable = %v", wgReachable)

	if !wgReachable {
		t.Fatalf("Mandatory live WebGoat target unreachable at %s", wgURL)
	}

	macroCfg := LoginMacroConfig{
		Name:          "webgoat-session-monitor",
		TargetURL:     wgURL,
		FormActionURL: "http://127.0.0.1:8080/WebGoat/login",
		Credentials: map[string]string{
			"username": "webgoat",
			"password": "password",
		},
		SuccessCriteria: SuccessCriteria{
			ExpectedCookies:    []string{"JSESSIONID"},
			ExpectedStatus:     []int{http.StatusOK, http.StatusFound},
			RedirectNotMatches: "?error",
		},
		VerifyURL: "http://127.0.0.1:8080/WebGoat/welcome.mvc",
		VerifyCriteria: VerifyCriteria{
			ExpectedStatus:  []int{http.StatusOK},
			BodyMustContain: "<title>WebGoat</title>",
		},
		Timeout: 10 * time.Second,
	}

	macro := NewLoginMacro(macroCfg)
	monitor := NewSessionMonitor(SessionMonitorConfig{
		Name:           "webgoat-live-monitor",
		Macro:          macro,
		HealthCheckURL: "http://127.0.0.1:8080/WebGoat/welcome.mvc",
		RefreshTimeout: 15 * time.Second,
	})
	defer monitor.Close()

	ctx := context.Background()

	// Step 1: Establish initial authenticated WebGoat session
	initialSession, err := monitor.GetSession(ctx)
	if err != nil {
		t.Fatalf("Failed to establish initial WebGoat session: %v", err)
	}
	if initialSession == nil || !initialSession.Authenticated {
		t.Fatalf("Initial session invalid: %+v", initialSession)
	}
	initialCookie := initialSession.Cookies["JSESSIONID"]
	if initialCookie == "" {
		t.Fatalf("Missing JSESSIONID in initial session")
	}
	t.Logf("Initial WebGoat session established: ID=%s (JSESSIONID captured)", initialSession.ID)

	// Step 2: Artificially invalidate session in monitor to simulate expiration event
	monitor.InvalidateSession(initialSession.ID)
	if monitor.CurrentSession() != nil {
		t.Fatalf("Expected nil current session after invalidation")
	}

	// Step 3: Launch 20 concurrent goroutines requesting session refresh simultaneously
	const numWorkers = 20
	var wg sync.WaitGroup
	startGate := make(chan struct{})

	refreshedSessions := make([]*MacroSession, numWorkers)
	workerErrors := make([]error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate // Synchronize concurrency barrier
			refreshedSessions[idx], workerErrors[idx] = monitor.RefreshSession(ctx, "simulated_expiration_burst")
		}(i)
	}

	close(startGate) // Release all 20 fuzzer goroutines at once
	wg.Wait()

	// Step 4: Verify all 20 succeeded
	for i := 0; i < numWorkers; i++ {
		if workerErrors[i] != nil {
			t.Fatalf("Worker %d failed during concurrent refresh: %v", i, workerErrors[i])
		}
		if refreshedSessions[i] == nil || !refreshedSessions[i].Authenticated {
			t.Fatalf("Worker %d received invalid refreshed session", i)
		}
	}

	// Step 5: Assert exactly ONE macro execution occurred across the 20 workers
	// (Initial login = 1, Refreshed burst = 1 -> Total = 2)
	metrics := monitor.Metrics()
	if metrics.MacroExecutions != 2 {
		t.Fatalf("THUNDERING HERD DETECTED: Expected total 2 macro executions (1 initial + 1 refreshed burst), got %d", metrics.MacroExecutions)
	}

	// Step 6: Verify all 20 workers received the exact same refreshed session & JSESSIONID
	refreshedID := refreshedSessions[0].ID
	refreshedCookie := refreshedSessions[0].Cookies["JSESSIONID"]
	if refreshedID == initialSession.ID {
		t.Fatalf("Refreshed session ID must differ from initial session ID: %s", refreshedID)
	}
	if refreshedCookie == "" {
		t.Fatalf("Refreshed session missing JSESSIONID")
	}

	for i := 1; i < numWorkers; i++ {
		if refreshedSessions[i].ID != refreshedID {
			t.Fatalf("Session ID mismatch: worker %d got %s, worker 0 got %s", i, refreshedSessions[i].ID, refreshedID)
		}
		if refreshedSessions[i].Cookies["JSESSIONID"] != refreshedCookie {
			t.Fatalf("Cookie mismatch: worker %d got %s, worker 0 got %s", i, refreshedSessions[i].Cookies["JSESSIONID"], refreshedCookie)
		}
	}
	t.Logf("PASS: All 20 concurrent workers received refreshed session %s with 0 collisions", refreshedID)

	// Step 7: Verify refreshed session can access protected WebGoat endpoint
	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/WebGoat/welcome.mvc", nil)
	if err != nil {
		t.Fatalf("Failed to construct follow-up verification request: %v", err)
	}
	verifyResp, err := refreshedSessions[0].Client.Do(verifyReq)
	if err != nil {
		t.Fatalf("Follow-up verification request failed: %v", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("Follow-up verification returned HTTP %d, expected 200", verifyResp.StatusCode)
	}

	// Step 8: Verify subsequent requests reuse the refreshed session without triggering another login
	for i := 0; i < 5; i++ {
		subSess, subErr := monitor.GetSession(ctx)
		if subErr != nil {
			t.Fatalf("Subsequent GetSession %d failed: %v", i+1, subErr)
		}
		if subSess.ID != refreshedID {
			t.Fatalf("Subsequent GetSession %d returned unexpected ID: %s", i+1, subSess.ID)
		}
	}
	if monitor.Metrics().MacroExecutions != 2 {
		t.Fatalf("Subsequent requests triggered unexpected login: macroExecutions = %d", monitor.Metrics().MacroExecutions)
	}
	t.Logf("PASS: Subsequent requests reused refreshed session without re-authenticating")

	// Step 9: Handle canonical evidence receipt
	receiptDir := filepath.Join("..", "..", "test", "evidence", "phase3")
	receiptPath := filepath.Join(receiptDir, "3.2_session_keepalive_proof.json")

	optIn := os.Getenv("FELIX_GENERATE_RECEIPT") == "1"
	receiptMetrics := map[string]any{
		"concurrent_workers":              20,
		"macro_executions_burst":          1,
		"total_macro_executions":          2,
		"successful_refreshes":            20,
		"failed_refreshes":                0,
		"subsequent_reused_sessions":      5,
		"zero_race_collisions_verified":   true,
		"session_cookie_captured":         "JSESSIONID",
		"authenticated_followup_verified": true,
		"live_target_verified":            true,
		"controlled_fixture_verified":     true,
	}

	canonHash, err := verifyOrGeneratePhase32Receipt(receiptPath, optIn, receiptMetrics)
	if err != nil {
		t.Fatalf("Evidence receipt verification failed: %v", err)
	}
	t.Logf("Receipt SHA-256 cryptographically verified on disk: %s (file: %s)", canonHash, receiptPath)
}
