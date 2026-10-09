package sessionsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"felix/pkg/report"
)

// 1. Test TestPlan Generation and Prerequisites Checking
func TestSessionSec_Plan(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())

	// Context with full capabilities
	actxFull := &AssessmentContext{
		AssessmentID: "asm-plan-full",
		BaseURL:      "https://example.com",
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/login", Type: "login"},
			{Method: "POST", Path: "/logout", Type: "logout"},
			{Method: "GET", Path: "/profile", Type: "protected"},
			{Method: "POST", Path: "/reset-password", Type: "recovery"},
			{Method: "POST", Path: "/auth/refresh", Type: "refresh"},
			{Method: "GET", Path: "/onboarding/step2", Type: "multistep"},
		},
		Identities: []TestIdentity{
			{Alias: "admin", Role: "admin", PrivilegeLevel: 5},
			{Alias: "user", Role: "user", PrivilegeLevel: 1},
		},
	}

	plan, err := engine.Plan(context.Background(), actxFull)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if plan.TotalTests != 11 {
		t.Fatalf("expected 11 total planned tests, got %d", plan.TotalTests)
	}
	if plan.ReadyTests != 11 {
		t.Errorf("expected all 11 tests to be READY in full context, got %d ready, %d blocked", plan.ReadyTests, plan.BlockedTests)
	}

	// Context with zero endpoints and zero identities -> should block prerequisite-heavy tests
	actxEmpty := &AssessmentContext{
		AssessmentID: "asm-plan-empty",
		BaseURL:      "https://example.com",
	}
	planEmpty, err := engine.Plan(context.Background(), actxEmpty)
	if err != nil {
		t.Fatalf("Plan on empty context failed: %v", err)
	}
	if planEmpty.BlockedTests < 5 {
		t.Errorf("expected at least 5 blocked tests on empty context, got %d", planEmpty.BlockedTests)
	}
}

// 2. Category A: Session Fixation (Rotation vs Unrotated vs Distinct Cookies)
func TestSessionSec_CategoryA_SessionFixation(t *testing.T) {
	// Vulnerable server: preserves pre-auth session cookie upon login
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "pre_auth_fixed_token_123", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/login" {
			// Adopts the pre-auth session without rotating
			cookie, err := r.Cookie("session")
			if err == nil {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: cookie.Value, Path: "/"})
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vulnServer.Close()

	// Safe server: issues fresh rotated session cookie upon login
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "pre_auth_token_999", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fresh_rotated_authenticated_token_456", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Vulnerable unrotated fixation -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-fixation-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/login", Type: "login"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSessionFixation(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified fixation finding, got %d (findings: %d)", covVuln.Verified, len(findingsVuln))
	}
	if resultsVuln[0].VerificationState != StateVerified {
		t.Errorf("expected StateVerified, got %v", resultsVuln[0].VerificationState)
	}
	// Assert no raw token disclosure
	if strings.Contains(resultsVuln[0].EvidenceSummary, "pre_auth_fixed_token_123") {
		t.Errorf("raw session token leaked in evidence: %s", resultsVuln[0].EvidenceSummary)
	}

	// Negative Control: Safely rotated session -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-fixation-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/login", Type: "login"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessSessionFixation(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 3. Category B: Cookie Security Attributes and URL Exposure
func TestSessionSec_CategoryB_CookieSecurity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session cookie missing HttpOnly and Secure
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "secret_sess_val", Path: "/"})
		// Safe analytics cookie
		http.SetCookie(w, &http.Cookie{Name: "ga_tracker", Value: "track_123", Path: "/"})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-cookie-test",
		BaseURL:      server.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/", Parameters: []string{"session_id"}},
		},
	}

	results, findings, cov := engine.assessCookieSecurity(context.Background(), actx, server.Client())
	if cov.Verified != 1 {
		t.Errorf("expected 1 verified URL exposure issue, got %d", cov.Verified)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for URL exposure, got %d", len(findings))
	}
	if cov.Candidates < 1 {
		t.Errorf("expected at least 1 candidate for missing cookie flags, got %d", cov.Candidates)
	}

	// Assert zero raw tokens in output
	for _, r := range results {
		if strings.Contains(r.EvidenceSummary, "secret_sess_val") {
			t.Errorf("raw session leaked in result: %s", r.EvidenceSummary)
		}
	}
}

// 4. Category C: Session Invalidation and Timeout
func TestSessionSec_CategoryC_SessionInvalidation(t *testing.T) {
	// Vulnerable server: accepts invalidated session
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"profile": "user_data", "email": "test@example.com"}`)
	}))
	defer vulnServer.Close()

	// Safe server: rejects invalidated session with 401
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session-Status") == "invalidated" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "session expired"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"profile": "user_data"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-inval-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/profile", Type: "protected"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSessionInvalidation(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified session invalidation failure, got %d", covVuln.Verified)
	}
	if resultsVuln[0].VerificationState != StateVerified {
		t.Errorf("expected StateVerified, got %v", resultsVuln[0].VerificationState)
	}

	// Negative Control -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-inval-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/profile", Type: "protected"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessSessionInvalidation(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 5. Category D: Authentication-State Inconsistencies
func TestSessionSec_CategoryD_AuthStateInconsistency(t *testing.T) {
	// Vulnerable server: unauthenticated anonymous request reaches admin settings
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Admin Settings</h1><p>Secret API Key: 12345</p></body></html>`)
	}))
	defer vulnServer.Close()

	// Safe server: unauthenticated anonymous request rejected with 401
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "unauthorized"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Anonymous Bypass -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-authstate-vuln",
		BaseURL:      vulnServer.URL,
		Endpoints:    []TargetEndpoint{{Method: "GET", Path: "/admin/settings", Type: "protected"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessAuthStateInconsistency(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified auth state inconsistency finding, got %d", covVuln.Verified)
	}
	if resultsVuln[0].Severity != report.SeverityCritical {
		t.Errorf("expected SeverityCritical for unauthenticated admin access, got %v", resultsVuln[0].Severity)
	}

	// Negative Control -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-authstate-safe",
		BaseURL:      safeServer.URL,
		Endpoints:    []TargetEndpoint{{Method: "GET", Path: "/admin/settings", Type: "protected"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessAuthStateInconsistency(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 6. Category E: Token Handling (JWT alg:none & Refresh Rotation)
func TestSessionSec_CategoryE_TokenHandling(t *testing.T) {
	// Vulnerable server: accepts unsigned JWT alg:none and reused refresh tokens
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, "eyJhbGciOiJub25l") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status": "admin_granted"}`)
			return
		}
		if r.Method == "POST" && r.Header.Get("X-Token-State") == "consumed" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"access_token": "fresh_access_token_123"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer vulnServer.Close()

	// Safe server: rejects alg:none and consumed refresh tokens
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "invalid token"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: alg:none and refresh token reuse -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-token-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/api/auth/token", Type: "refresh"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessTokenHandling(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 2 || covVuln.Verified != 2 || len(findingsVuln) != 2 {
		t.Fatalf("expected 2 verified token flaws (alg:none and refresh rotation), got %d (findings: %d, results: %d)", covVuln.Verified, len(findingsVuln), len(resultsVuln))
	}

	// Negative Control: Safe server -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-token-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/api/auth/token", Type: "refresh"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessTokenHandling(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	for _, r := range resultsSafe {
		if r.VerificationState != StateNotVulnerable {
			t.Errorf("expected StateNotVulnerable for safe token handling, got %v", r.VerificationState)
		}
	}
}

// 7. Category F: Privilege Transitions (Role Downgrade Enforcement)
func TestSessionSec_CategoryF_PrivilegeTransitions(t *testing.T) {
	// Vulnerable server: downgraded user session retains administrative access
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"admin_dashboard": "active"}`)
	}))
	defer vulnServer.Close()

	// Safe server: downgraded user session denied access
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error": "forbidden: insufficient privileges"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-priv-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/api/admin/roles", Type: "admin"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessPrivilegeTransitions(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified privilege transition finding, got %d", covVuln.Verified)
	}

	// Negative Control -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-priv-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/api/admin/roles", Type: "admin"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessPrivilegeTransitions(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 8. Category G: Logout Behavior (Server-Side Session Termination)
func TestSessionSec_CategoryG_LogoutBehavior(t *testing.T) {
	// Vulnerable server: clears cookie in logout response, but still accepts session on replay
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/profile" {
			// Accepts replayed session
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"profile": "user_data"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vulnServer.Close()

	// Safe server: rejects replayed session with 401 after logout
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/profile" {
			if r.Header.Get("X-Logout-Tested") == "true" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Incomplete Logout -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-logout-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/logout", Type: "logout"},
			{Method: "GET", Path: "/profile", Type: "protected"},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessLogoutBehavior(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified incomplete logout finding, got %d", covVuln.Verified)
	}

	// Negative Control: Safe Logout -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-logout-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/logout", Type: "logout"},
			{Method: "GET", Path: "/profile", Type: "protected"},
		},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessLogoutBehavior(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 9. Category H: Password Reset & Account Recovery
func TestSessionSec_CategoryH_PasswordRecovery(t *testing.T) {
	// Vulnerable server: accepts consumed reset token
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "success", "message": "password updated"}`)
	}))
	defer vulnServer.Close()

	// Safe server: rejects consumed reset token
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error": "token already used"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Reusable Token -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-recov-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/reset-password", Type: "recovery"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessPasswordRecovery(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified recovery token replay finding, got %d", covVuln.Verified)
	}

	// Negative Control: Safe Server -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-recov-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "POST", Path: "/reset-password", Type: "recovery"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessPasswordRecovery(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 10. Category I: Account Enumeration
func TestSessionSec_CategoryI_AccountEnumeration(t *testing.T) {
	// Vulnerable server: reveals existence via distinct messages
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.Form.Get("username")
		if strings.Contains(username, "existing") {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "Incorrect password"}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error": "User does not exist"}`)
		}
	}))
	defer vulnServer.Close()

	// Safe server: uniform generic response
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "Invalid credentials"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Enumeration Discrepancy -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-enum-vuln",
		BaseURL:      vulnServer.URL,
		Endpoints:    []TargetEndpoint{{Method: "POST", Path: "/login", Type: "login"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessAccountEnumeration(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified account enumeration finding, got %d", covVuln.Verified)
	}

	// Negative Control: Uniform Responses -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-enum-safe",
		BaseURL:      safeServer.URL,
		Endpoints:    []TargetEndpoint{{Method: "POST", Path: "/login", Type: "login"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessAccountEnumeration(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 11. Category J: Session Puzzling & Workflow State Confusion
func TestSessionSec_CategoryJ_SessionPuzzling(t *testing.T) {
	// Vulnerable server: accepts pre-auth step cookie to skip authentication
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("workflow_step")
		if err == nil && cookie.Value == "verification_passed" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Welcome to Dashboard</h1></body></html>`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer vulnServer.Close()

	// Safe server: strictly enforces authentication regardless of step cookie
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "authentication required"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Session Puzzling -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-puzzling-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/onboarding/step2", Type: "multistep"}},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSessionPuzzling(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified session puzzling finding, got %d", covVuln.Verified)
	}

	// Negative Control: Safe Server -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-puzzling-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/onboarding/step2", Type: "multistep"}},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessSessionPuzzling(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 12. Category K: Concurrent Sessions & Cross-Session Isolation
func TestSessionSec_CategoryK_SessionIsolation(t *testing.T) {
	// Vulnerable server: User A accesses User B's private endpoint
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"secret_user_b_private": "confidential_record_777"}`)
	}))
	defer vulnServer.Close()

	// Safe server: rejects cross-user access with 403
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error": "access denied to peer resource"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Isolation Failure -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-iso-vuln",
		BaseURL:          vulnServer.URL,
		SyntheticFixture: true,
		Identities: []TestIdentity{
			{Alias: "user_a", Role: "user"},
			{Alias: "user_b", Role: "user"},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSessionIsolation(context.Background(), actxVuln, vulnServer.Client())
	if len(resultsVuln) != 1 || covVuln.Verified != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified cross-session isolation finding, got %d", covVuln.Verified)
	}

	// Negative Control: Safe Server -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-iso-safe",
		BaseURL:          safeServer.URL,
		SyntheticFixture: true,
		Identities: []TestIdentity{
			{Alias: "user_a", Role: "user"},
			{Alias: "user_b", Role: "user"},
		},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessSessionIsolation(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(findingsSafe) != 0 {
		t.Errorf("expected 0 verified findings on safe server, got %d", covSafe.Verified)
	}
	if resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", resultsSafe[0].VerificationState)
	}
}

// 13. Test Scoped Client Redirect Enforcement
func TestSessionSec_ScopedRedirectEnforcement(t *testing.T) {
	outServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Out of scope content")
	}))
	defer outServer.Close()

	inServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outServer.URL, http.StatusFound)
	}))
	defer inServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-redir-test",
		BaseURL:      inServer.URL,
		IsAllowed: func(u string) bool {
			return strings.HasPrefix(u, inServer.URL)
		},
		IsExcluded: func(u string) bool {
			return strings.Contains(u, "excluded")
		},
	}

	client := engine.scopedClient(actx)
	req, _ := http.NewRequest("GET", inServer.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatalf("expected redirect to out-of-scope destination to be blocked fail-closed")
	}
	if !strings.Contains(err.Error(), "out of authorized scope") {
		t.Errorf("expected scope violation error, got %v", err)
	}
}

// 14. Test Dry-Run Assessment Execution
func TestSessionSec_DryRun(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-dryrun",
		BaseURL:      "https://example.com",
		DryRun:       true,
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/login", Type: "login"},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("DryRun assess failed: %v", err)
	}
	if len(results) != 0 || len(findings) != 0 {
		t.Errorf("dry run must produce zero active results and zero findings, got %d results, %d findings", len(results), len(findings))
	}
	if summary == nil || summary.CategoriesCovered != 11 {
		t.Errorf("expected 11 categories covered in dry run summary, got %+v", summary)
	}
}
