package sessionsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
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

// 15. Test Cookie Parsing, Case-Insensitive Attributes, and Prefix Rules
func TestSessionSec_CookieParsingAndPrefixRules(t *testing.T) {
	// Raw Set-Cookie header with comma in Expires and case-insensitive attributes
	rawHeader := "session_token=secret_val_123; EXPIRES=Wed, 21 Oct 2026 07:28:00 GMT; PATH=/; HTTPONLY; SECURE; SameSite=Strict"
	cookies := ParseSetCookieHeaders([]string{rawHeader})
	if len(cookies) != 1 {
		t.Fatalf("expected 1 parsed cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "session_token" || c.Value != "secret_val_123" {
		t.Errorf("unexpected name/val: %s=%s", c.Name, c.Value)
	}
	if !c.HttpOnly || !c.Secure {
		t.Errorf("expected HttpOnly and Secure to be true, got HttpOnly=%t, Secure=%t", c.HttpOnly, c.Secure)
	}
	if c.Path != "/" {
		t.Errorf("expected Path=/, got %s", c.Path)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode, got %v", c.SameSite)
	}
	if c.Expires.IsZero() {
		t.Errorf("expected non-zero parsed Expires date")
	}

	// __Host- prefix tests
	// Case 1: Bad __Host- cookie missing Secure and specifying Domain
	badHostCookie := &ParsedCookie{
		Name:      "__Host-sess",
		Value:     "bad_host_val",
		Path:      "/api", // should be /
		Domain:    "example.com", // should be empty
		Secure:    false, // must be true
		HttpOnly:  true,
		HasDomain: true,
		HasPath:   true,
	}
	defects, _ := EvaluateCookieAttributes(badHostCookie, "https://example.com")
	foundSecureDefect, foundPathDefect, foundDomainDefect := false, false, false
	for _, d := range defects {
		if strings.Contains(d.Code, "NO-SECURE") {
			foundSecureDefect = true
		}
		if strings.Contains(d.Code, "PATH") {
			foundPathDefect = true
		}
		if strings.Contains(d.Code, "DOMAIN") {
			foundDomainDefect = true
		}
	}
	if !foundSecureDefect || !foundPathDefect || !foundDomainDefect {
		t.Errorf("expected __Host- violations for secure, path, and domain, got: %+v", defects)
	}

	// Case 2: Good __Host- cookie
	goodHostCookie := &ParsedCookie{
		Name:        "__Host-sess",
		Value:       "good_host_val",
		Path:        "/",
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteStrictMode,
		HasPath:     true,
		HasSecure:   true,
		HasHttpOnly: true,
		HasSameSite: true,
	}
	goodDefects, _ := EvaluateCookieAttributes(goodHostCookie, "https://example.com")
	if len(goodDefects) != 0 {
		t.Errorf("expected 0 defects for valid __Host- cookie, got: %+v", goodDefects)
	}

	// Non-session cookies: Anti-CSRF and Analytics
	csrfCookie := &ParsedCookie{
		Name:        "XSRF-TOKEN",
		Value:       "csrf_val_abc",
		Path:        "/",
		Secure:      true,
		HttpOnly:    false, // Legitimate double-submit pattern
		SameSite:    http.SameSiteLaxMode,
		HasSameSite: true,
	}
	csrfDefects, isSession := EvaluateCookieAttributes(csrfCookie, "https://example.com")
	if isSession {
		t.Errorf("expected XSRF-TOKEN not to be classified as session cookie")
	}
	if len(csrfDefects) != 0 {
		t.Errorf("expected 0 defects for standard double-submit CSRF cookie, got: %+v", csrfDefects)
	}

	// SameSite=None without Secure
	sameSiteNoneInsecure := &ParsedCookie{
		Name:        "sess_cookie",
		Value:       "val",
		SameSite:    http.SameSiteNoneMode,
		Secure:      false,
		HttpOnly:    true,
		HasSameSite: true,
	}
	ssDefects, _ := EvaluateCookieAttributes(sameSiteNoneInsecure, "https://example.com")
	foundSSNone := false
	for _, d := range ssDefects {
		if strings.Contains(d.Code, "SAMESITE-NONE-INSECURE") {
			foundSSNone = true
		}
	}
	if !foundSSNone {
		t.Errorf("expected SameSite=None without Secure defect, got: %+v", ssDefects)
	}
}

// 16. Test Remote Cleartext HTTP Cookie Transport Guard
func TestSessionSec_InsecureCleartextRemoteHTTP(t *testing.T) {
	cookie := &ParsedCookie{
		Name:        "session_id",
		Value:       "secret_token_cleartext",
		Path:        "/",
		Secure:      false,
		HttpOnly:    true,
		SameSite:    http.SameSiteLaxMode,
		HasSameSite: true,
	}
	// Remote HTTP target (not loopback)
	defects, isSession := EvaluateCookieAttributes(cookie, "http://api.production-server.com")
	if !isSession {
		t.Fatalf("expected session_id to be classified as session cookie")
	}
	foundCleartext := false
	for _, d := range defects {
		if d.Code == "SS-COOKIE-CLEARTEXT" {
			foundCleartext = true
		}
	}
	if !foundCleartext {
		t.Errorf("expected SS-COOKIE-CLEARTEXT defect for remote cleartext HTTP, got: %+v", defects)
	}
}

// 17. Test Cross-Origin Redirect Credential Stripping
func TestSessionSec_CrossOriginRedirectCredentialStripping(t *testing.T) {
	var targetReceivedAuth, targetReceivedCookie string
	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReceivedAuth = r.Header.Get("Authorization")
		targetReceivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer destServer.Close()

	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destServer.URL, http.StatusFound)
	}))
	defer originServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-cross-origin",
		BaseURL:      originServer.URL,
		IsAllowed: func(u string) bool {
			return true // Allow all for this test to observe credential behavior
		},
	}

	client := engine.scopedClient(actx)
	req, _ := http.NewRequest("GET", originServer.URL, nil)
	req.Header.Set("Authorization", "Bearer sensitive_secret_token_xyz")
	req.Header.Set("Cookie", "session=sensitive_cookie_val_abc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client Do failed: %v", err)
	}
	defer resp.Body.Close()

	if targetReceivedAuth != "" {
		t.Errorf("expected Authorization header to be stripped across origin redirect, got: %s", targetReceivedAuth)
	}
	if targetReceivedCookie != "" {
		t.Errorf("expected Cookie header to be stripped across origin redirect, got: %s", targetReceivedCookie)
	}
}

// 18. Test Authorization Gate Fail-Closed in Engine
func TestSessionSec_AuthorizationGateFailClosed(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())

	// 1. Missing Authorization record on non-fixture context -> must fail closed
	actxMissing := &AssessmentContext{
		AssessmentID:     "asm-auth-missing",
		BaseURL:          "https://example.com",
		SyntheticFixture: false,
		DryRun:           false,
	}
	_, _, _, errMissing := engine.Assess(context.Background(), actxMissing)
	if errMissing == nil || !strings.Contains(errMissing.Error(), "security refusal: authorization record required") {
		t.Errorf("expected error for missing authorization, got %v", errMissing)
	}

	// 2. Expired Authorization record -> must fail closed
	now := time.Now().UTC()
	validFrom := now.Add(-48 * time.Hour)
	validUntil := now.Add(-24 * time.Hour)
	actxExpired := &AssessmentContext{
		AssessmentID:     "asm-auth-expired",
		BaseURL:          "https://example.com",
		SyntheticFixture: false,
		DryRun:           false,
		Authorization: &auth.AuthorizationRecord{
			ID:               "auth-expired",
			Status:           "APPROVED",
			ValidFrom:        &validFrom,
			ValidUntil:       &validUntil,
			AuthorizingParty: "Security Officer",
		},
	}
	_, _, _, errExpired := engine.Assess(context.Background(), actxExpired)
	if errExpired == nil || !strings.Contains(errExpired.Error(), "security refusal: authorization is invalid") {
		t.Errorf("expected error for expired authorization, got %v", errExpired)
	}
}

// 19. Test Zero-Knowledge Sensitive Token Redaction Sentinel
func TestSessionSec_SentinelLeakPrevention(t *testing.T) {
	canarySessionToken := "flx_sentinel_secret_cookie_token_9876543210"
	canaryPassword := "flx_sentinel_pass_secret_abc1234567"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{
				Name:  "session_token",
				Value: canarySessionToken,
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-sentinel-leak-test",
		ExecutionID:      "exec-sentinel-1",
		BaseURL:          server.URL,
		SyntheticFixture: true,
		Identities: []TestIdentity{
			{
				Alias:    "user_sentinel",
				Role:     "user",
				Username: "canary_user",
				Password: canaryPassword,
			},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	// Serialize results to JSON
	bytesResults, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("json.Marshal results failed: %v", err)
	}
	jsonResults := string(bytesResults)

	// Serialize findings to JSON
	bytesFindings, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("json.Marshal findings failed: %v", err)
	}
	jsonFindings := string(bytesFindings)

	// Serialize summary to JSON
	bytesSummary, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal summary failed: %v", err)
	}
	jsonSummary := string(bytesSummary)

	// Assert zero exposure of raw secret canary token
	if strings.Contains(jsonResults, canarySessionToken) {
		t.Fatalf("SECURITY VIOLATION: Canary session token leaked in results JSON: %s", jsonResults)
	}
	if strings.Contains(jsonFindings, canarySessionToken) {
		t.Fatalf("SECURITY VIOLATION: Canary session token leaked in findings JSON: %s", jsonFindings)
	}
	if strings.Contains(jsonSummary, canarySessionToken) {
		t.Fatalf("SECURITY VIOLATION: Canary session token leaked in summary JSON: %s", jsonSummary)
	}

	// Assert zero exposure of raw secret canary password
	if strings.Contains(jsonResults, canaryPassword) {
		t.Fatalf("SECURITY VIOLATION: Canary password leaked in results JSON")
	}
	if strings.Contains(jsonFindings, canaryPassword) {
		t.Fatalf("SECURITY VIOLATION: Canary password leaked in findings JSON")
	}
	if strings.Contains(jsonSummary, canaryPassword) {
		t.Fatalf("SECURITY VIOLATION: Canary password leaked in summary JSON")
	}
}

// 20. Test Session Invalidation False Positive Protection (Login Redirects & Forms)
func TestSessionSec_InvalidationLoginRedirectNotVulnerable(t *testing.T) {
	// Server returns HTTP 200 with an HTML login form when session is revoked
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h2>Please Sign In</h2><form action="/login" method="POST"><input type="password" name="password"></form></body></html>`)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-inval-redirect",
		BaseURL:          server.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/profile", Type: "protected"}},
	}

	results, findings, cov := engine.assessSessionInvalidation(context.Background(), actx, server.Client())
	if cov.Verified != 0 || len(findings) != 0 {
		t.Fatalf("expected 0 verified findings when server renders login form on invalidation, got %d (findings: %d)", cov.Verified, len(findings))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %v", results[0].VerificationState)
	}
}

// 21. Test Origin Port Mismatch Credential Stripping
func TestSessionSec_OriginPortMismatchCredentialStripping(t *testing.T) {
	var targetHeaders http.Header
	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer destServer.Close()

	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destServer.URL, http.StatusFound)
	}))
	defer originServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-port-mismatch",
		BaseURL:      originServer.URL,
		IsAllowed: func(u string) bool {
			return true
		},
	}

	client := engine.scopedClient(actx)
	req, _ := http.NewRequest("GET", originServer.URL, nil)
	for _, h := range SensitiveCredentialHeaders {
		req.Header.Set(h, "sensitive_secret_val_123")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client Do failed: %v", err)
	}
	defer resp.Body.Close()

	for _, h := range SensitiveCredentialHeaders {
		if val := targetHeaders.Get(h); val != "" {
			t.Errorf("expected sensitive header %q to be stripped across port-mismatched redirect, got: %s", h, val)
		}
	}
}

// 22. Test Origin Comparison and Scheme Downgrade Defense
func TestSessionSec_OriginComparisonAndSchemeDowngradeDefense(t *testing.T) {
	// 1. IsSameOrigin checks
	u1, _ := url.Parse("https://example.com")
	u2, _ := url.Parse("https://example.com:443")
	u3, _ := url.Parse("http://example.com:80")
	u4, _ := url.Parse("https://example.com:8443")
	u5, _ := url.Parse("https://sub.example.com")

	if !IsSameOrigin(u1, u2) {
		t.Errorf("expected https://example.com and https://example.com:443 to be same origin")
	}
	if IsSameOrigin(u1, u3) {
		t.Errorf("expected https vs http to NOT be same origin (scheme mismatch)")
	}
	if IsSameOrigin(u1, u4) {
		t.Errorf("expected 443 vs 8443 to NOT be same origin (port mismatch)")
	}
	if IsSameOrigin(u1, u5) {
		t.Errorf("expected example.com vs sub.example.com to NOT be same origin (host mismatch)")
	}

	// 2. Client CheckRedirect scheme downgrade credential stripping
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-scheme-downgrade",
		BaseURL:      "https://example.com",
		IsAllowed:    func(string) bool { return true },
	}
	client := engine.scopedClient(actx)

	reqRedirect, _ := http.NewRequest("GET", "http://example.com/api", nil)
	reqRedirect.Header.Set("Authorization", "Bearer sensitive_token")
	reqRedirect.Header.Set("Cookie", "session=secret")

	viaReq, _ := http.NewRequest("GET", "https://example.com/login", nil)
	viaReq.Header.Set("Authorization", "Bearer sensitive_token")
	viaReq.Header.Set("Cookie", "session=secret")

	err := client.CheckRedirect(reqRedirect, []*http.Request{viaReq})
	if err != nil {
		t.Fatalf("unexpected CheckRedirect error: %v", err)
	}

	if val := reqRedirect.Header.Get("Authorization"); val != "" {
		t.Errorf("expected Authorization to be stripped on HTTPS->HTTP scheme downgrade, got %q", val)
	}
	if val := reqRedirect.Header.Get("Cookie"); val != "" {
		t.Errorf("expected Cookie to be stripped on HTTPS->HTTP scheme downgrade, got %q", val)
	}
}

// 23. Test Chained Redirect Credential Defense
func TestSessionSec_ChainedRedirectUntrustedOrigin(t *testing.T) {
	var targetHeaders http.Header
	cServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer cServer.Close()

	bServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cServer.URL, http.StatusFound)
	}))
	defer bServer.Close()

	aServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bServer.URL, http.StatusFound)
	}))
	defer aServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-chained-redirect",
		BaseURL:      aServer.URL,
		IsAllowed:    func(string) bool { return true },
	}

	client := engine.scopedClient(actx)
	req, _ := http.NewRequest("GET", aServer.URL, nil)
	req.Header.Set("Authorization", "Bearer chained_secret_token")
	req.Header.Set("Cookie", "session=chained_cookie")
	req.Header.Set("X-API-Key", "chained_api_key")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client Do failed: %v", err)
	}
	defer resp.Body.Close()

	if val := targetHeaders.Get("Authorization"); val != "" {
		t.Errorf("expected Authorization to be stripped across chained redirect, got: %s", val)
	}
	if val := targetHeaders.Get("Cookie"); val != "" {
		t.Errorf("expected Cookie to be stripped across chained redirect, got: %s", val)
	}
	if val := targetHeaders.Get("X-API-Key"); val != "" {
		t.Errorf("expected X-API-Key to be stripped across chained redirect, got: %s", val)
	}
}

// 24. Test Remote Cleartext Transport Credential Withholding
type mockTransport struct {
	lastReq *http.Request
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.lastReq = req
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, nil
}

func TestSessionSec_RemoteCleartextTransportCredentialWithholding(t *testing.T) {
	mock := &mockTransport{}
	guarded := &credentialGuardedTransport{base: mock}

	// 1. Remote unencrypted HTTP -> Credentials MUST be withheld
	reqRemote, _ := http.NewRequest("GET", "http://api.remote-unencrypted-example.com/user", nil)
	reqRemote.Header.Set("Authorization", "Bearer top_secret_token")
	reqRemote.Header.Set("Cookie", "session=classified_session_id")
	reqRemote.Header.Set("X-API-Key", "api_key_secret")

	_, err := guarded.RoundTrip(reqRemote)
	if err != nil {
		t.Fatalf("guarded RoundTrip failed: %v", err)
	}

	if val := mock.lastReq.Header.Get("Authorization"); val != "" {
		t.Errorf("expected Authorization stripped on remote unencrypted HTTP, got: %s", val)
	}
	if val := mock.lastReq.Header.Get("Cookie"); val != "" {
		t.Errorf("expected Cookie stripped on remote unencrypted HTTP, got: %s", val)
	}
	if val := mock.lastReq.Header.Get("X-API-Key"); val != "" {
		t.Errorf("expected X-API-Key stripped on remote unencrypted HTTP, got: %s", val)
	}

	// 2. Loopback HTTP -> Credentials permitted for local testing / mock fixtures
	reqLoopback, _ := http.NewRequest("GET", "http://127.0.0.1:8080/user", nil)
	reqLoopback.Header.Set("Authorization", "Bearer loopback_token")
	reqLoopback.Header.Set("Cookie", "session=loopback_cookie")

	_, err = guarded.RoundTrip(reqLoopback)
	if err != nil {
		t.Fatalf("loopback RoundTrip failed: %v", err)
	}

	if val := mock.lastReq.Header.Get("Authorization"); val != "Bearer loopback_token" {
		t.Errorf("expected loopback to retain Authorization, got: %s", val)
	}
	if val := mock.lastReq.Header.Get("Cookie"); val != "session=loopback_cookie" {
		t.Errorf("expected loopback to retain Cookie, got: %s", val)
	}
}

// 25. Test Live Target Prerequisite Inconclusive Outcome
func TestSessionSec_LivePrerequisiteInconclusiveOutcome(t *testing.T) {
	// Server responds normally to pre-auth and logout endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "pre_auth_cookie_val", Path: "/"})
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	actx := &AssessmentContext{
		AssessmentID:     "asm-live-prereq-inconclusive",
		BaseURL:          server.URL,
		SyntheticFixture: false, // Live target mode
		Authorization: &auth.AuthorizationRecord{
			ID:                  "auth-live-test",
			AuthorizingParty:    "Security Team",
			AuthorizationMethod: "WRITTEN_APPROVAL",
			Status:              "APPROVED",
			ValidFrom:           &past,
			ValidUntil:          &future,
		},
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/login", Type: "login"},
			{Method: "POST", Path: "/logout", Type: "logout"},
			{Method: "GET", Path: "/profile", Type: "protected"},
			{Method: "POST", Path: "/reset-password", Type: "recovery"},
		},
		IsAllowed: func(string) bool { return true },
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	_ = findings
	if summary.InconclusiveCount == 0 {
		t.Fatalf("expected inconclusive tests when live prerequisites are absent, got %d", summary.InconclusiveCount)
	}

	// Verify that categories lacking live prerequisites are marked INCONCLUSIVE and BLOCKED_MISSING_PREREQUISITES
	prereqCategories := []SessionCategory{
		CategorySessionFixation,
		CategorySessionInvalidation,
		CategoryPrivilegeTransitions,
		CategoryLogoutBehavior,
		CategoryPasswordRecovery,
		CategorySessionPuzzling,
		CategorySessionIsolation,
	}

	for _, cat := range prereqCategories {
		cov, ok := summary.CoverageMap[string(cat)]
		if !ok {
			t.Errorf("missing coverage for category %s", cat)
			continue
		}
		if cov.Inconclusive == 0 {
			t.Errorf("category %s expected Inconclusive > 0, got %d", cat, cov.Inconclusive)
		}
		if cov.Status != CoverageBlockedMissingPrereq {
			t.Errorf("category %s expected status %s, got %s", cat, CoverageBlockedMissingPrereq, cov.Status)
		}
	}

	// Ensure results for these categories are StateInconclusive, never StateCandidate
	for _, res := range results {
		for _, cat := range prereqCategories {
			if res.Category == cat {
				if res.VerificationState == StateCandidate {
					t.Errorf("result %s for category %s was StateCandidate; expected StateInconclusive when prerequisites are absent",
						res.TestID, cat)
				}
			}
		}
	}
}

// 26. Test SplitSetCookieHeader With Complex Expires Dates
func TestSessionSec_SplitSetCookieHeaderExpiresHandling(t *testing.T) {
	header := "session_id=abc123xyz; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Secure; HttpOnly, user_pref=dark; Path=/; SameSite=Lax"
	cookies := SplitSetCookieHeader(header)

	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies split, got %d: %#v", len(cookies), cookies)
	}
	if !strings.HasPrefix(cookies[0], "session_id=abc123xyz") {
		t.Errorf("first cookie corrupted: %s", cookies[0])
	}
	if !strings.HasPrefix(cookies[1], "user_pref=dark") {
		t.Errorf("second cookie corrupted: %s", cookies[1])
	}
}

// 27. Test Redirect Return to Original Host Defense (A -> B -> A)
func TestSessionSec_RedirectOriginReturnToOriginalHost(t *testing.T) {
	var aFirstHeaders, bHeaders, aSecondHeaders http.Header
	var aCallCount int

	var bServerURL string
	var aServer *httptest.Server

	aServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aCallCount++
		if aCallCount == 1 {
			aFirstHeaders = r.Header.Clone()
			// Redirect to untrusted intermediate origin B
			http.Redirect(w, r, bServerURL, http.StatusFound)
			return
		}
		// Second call: redirected back from B to A
		aSecondHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer aServer.Close()

	bServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHeaders = r.Header.Clone()
		// Untrusted origin B redirects back to original origin A
		http.Redirect(w, r, aServer.URL, http.StatusFound)
	}))
	defer bServer.Close()
	bServerURL = bServer.URL

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-return-to-origin",
		BaseURL:      aServer.URL,
		IsAllowed:    func(string) bool { return true },
	}

	client := engine.scopedClient(actx)
	req, _ := http.NewRequest("GET", aServer.URL, nil)
	req.Header.Set("Authorization", "Bearer canary_return_token")
	req.Header.Set("Cookie", "session=canary_return_cookie")
	req.Header.Set("X-API-Key", "canary_return_key")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client Do failed: %v", err)
	}
	defer resp.Body.Close()

	// 1. Initial request to origin A has credentials
	if aFirstHeaders.Get("Authorization") != "Bearer canary_return_token" {
		t.Errorf("expected origin A first request to receive credentials")
	}

	// 2. Untrusted intermediate origin B must NOT receive credentials
	for _, h := range []string{"Authorization", "Cookie", "X-API-Key"} {
		if val := bHeaders.Get(h); val != "" {
			t.Errorf("SECURITY LEAK: untrusted origin B received %s=%s", h, val)
		}
	}

	// 3. Return to origin A must NOT have credentials forwarded or reinjected
	for _, h := range []string{"Authorization", "Cookie", "X-API-Key"} {
		if val := aSecondHeaders.Get(h); val != "" {
			t.Errorf("SECURITY LEAK: redirected return to origin A retained %s=%s", h, val)
		}
	}
}

// 28. Test Redirect Scheme Transition Bidirectional (HTTP <-> HTTPS)
func TestSessionSec_RedirectSchemeTransitionBidirectional(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-scheme-bidirectional",
		BaseURL:      "http://example.com",
		IsAllowed:    func(string) bool { return true },
	}
	client := engine.scopedClient(actx)

	// Case 1: HTTP -> HTTPS redirect
	reqHTTPtoHTTPS, _ := http.NewRequest("GET", "https://example.com/secure", nil)
	reqHTTPtoHTTPS.Header.Set("Authorization", "Bearer http_to_https_token")
	reqHTTPtoHTTPS.Header.Set("Cookie", "session=http_to_https_cookie")
	viaHTTP, _ := http.NewRequest("GET", "http://example.com/start", nil)

	err := client.CheckRedirect(reqHTTPtoHTTPS, []*http.Request{viaHTTP})
	if err != nil {
		t.Fatalf("unexpected CheckRedirect error: %v", err)
	}
	if val := reqHTTPtoHTTPS.Header.Get("Authorization"); val != "" {
		t.Errorf("expected Authorization stripped on HTTP->HTTPS scheme transition, got: %s", val)
	}
	if val := reqHTTPtoHTTPS.Header.Get("Cookie"); val != "" {
		t.Errorf("expected Cookie stripped on HTTP->HTTPS scheme transition, got: %s", val)
	}

	// Case 2: HTTPS -> HTTP redirect (scheme downgrade)
	reqHTTPStoHTTP, _ := http.NewRequest("GET", "http://example.com/insecure", nil)
	reqHTTPStoHTTP.Header.Set("Authorization", "Bearer https_to_http_token")
	reqHTTPStoHTTP.Header.Set("Cookie", "session=https_to_http_cookie")
	viaHTTPS, _ := http.NewRequest("GET", "https://example.com/secure", nil)

	err = client.CheckRedirect(reqHTTPStoHTTP, []*http.Request{viaHTTPS})
	if err != nil {
		t.Fatalf("unexpected CheckRedirect error: %v", err)
	}
	if val := reqHTTPStoHTTP.Header.Get("Authorization"); val != "" {
		t.Errorf("expected Authorization stripped on HTTPS->HTTP scheme downgrade, got: %s", val)
	}
	if val := reqHTTPStoHTTP.Header.Get("Cookie"); val != "" {
		t.Errorf("expected Cookie stripped on HTTPS->HTTP scheme downgrade, got: %s", val)
	}
}

// 29. Test Cookie Parser Advanced Delimiters, Optional Attributes & Malformed Headers
func TestSessionSec_CookieParser_AdvancedDelimitersAndMalformed(t *testing.T) {
	// 1. Multiple cookies with diverse Expires formats, Max-Age, Domain, Path, SameSite, Partitioned
	complexHeader := "sess_a=123; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/api; Domain=example.com; Secure; HttpOnly; SameSite=Strict; Partitioned, " +
		"sess_b=456; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax, " +
		"pref_c=dark; Path=/; SameSite=None; Secure"

	cookies := ParseSetCookieHeaders([]string{complexHeader})
	if len(cookies) != 3 {
		t.Fatalf("expected 3 parsed cookies, got %d", len(cookies))
	}

	cA := cookies[0]
	if cA.Name != "sess_a" || cA.Value != "123" || cA.Path != "/api" || cA.Domain != "example.com" {
		t.Errorf("cookie A fields mismatch: %#v", cA)
	}
	if !cA.Secure || !cA.HttpOnly || cA.SameSite != http.SameSiteStrictMode || !cA.Partitioned {
		t.Errorf("cookie A security flags mismatch: %#v", cA)
	}

	cB := cookies[1]
	if cB.Name != "sess_b" || cB.Value != "456" || cB.MaxAge != 3600 || cB.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie B fields mismatch: %#v", cB)
	}

	cC := cookies[2]
	if cC.Name != "pref_c" || cC.Value != "dark" || cC.SameSite != http.SameSiteNoneMode || !cC.Secure {
		t.Errorf("cookie C fields mismatch: %#v", cC)
	}

	// 2. Malformed headers: empty name, missing '=', extra semicolons, invalid attributes
	malformedHeaders := []string{
		"=missing_name; Path=/",
		"missing_eq; Path=/",
		";;;",
		"valid_cookie=xyz; ; Path=/; ; Secure;;",
		"bad_samesite=abc; SameSite=totally_invalid; HttpOnly",
		"bad_maxage=def; Max-Age=not_a_number; Path=/",
	}

	parsed := ParseSetCookieHeaders(malformedHeaders)
	// Only valid_cookie, bad_samesite, bad_maxage should parse as cookies
	if len(parsed) != 3 {
		t.Fatalf("expected exactly 3 validly parsed cookies from malformed inputs, got %d", len(parsed))
	}

	// valid_cookie should preserve Secure and Path=/ despite duplicate semicolons
	if parsed[0].Name != "valid_cookie" || !parsed[0].Secure || parsed[0].Path != "/" {
		t.Errorf("valid_cookie parsing failed: %#v", parsed[0])
	}
	// bad_samesite should fallback to DefaultMode
	if parsed[1].Name != "bad_samesite" || parsed[1].SameSite != http.SameSiteDefaultMode {
		t.Errorf("bad_samesite should default to DefaultMode, got: %v", parsed[1].SameSite)
	}
	// bad_maxage should not have HasMaxAge set
	if parsed[2].Name != "bad_maxage" || parsed[2].HasMaxAge {
		t.Errorf("bad_maxage should have HasMaxAge=false, got: %v", parsed[2].HasMaxAge)
	}
}

// 30. Test Cookie Parser Defect Unmasking Across Multiple Combined Cookies
func TestSessionSec_CookieParser_DefectUnmaskingAcrossMultipleCookies(t *testing.T) {
	// Header contains one secure cookie followed by an insecure session cookie without Secure/HttpOnly
	header := "auth_secure=token1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Secure; HttpOnly, " +
		"session_id=insecure_token2; Path=/; Domain=.com"

	parsed := ParseSetCookieHeaders([]string{header})
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed cookies, got %d", len(parsed))
	}

	// Evaluate second cookie: must uncover all defects (missing Secure, missing HttpOnly, overly broad domain)
	defects, isSession := EvaluateCookieAttributes(parsed[1], "https://example.com")
	if !isSession {
		t.Fatalf("expected session_id to be classified as session cookie")
	}

	foundNoSecure := false
	foundNoHttpOnly := false
	foundBroadDomain := false
	for _, d := range defects {
		switch d.Code {
		case "SS-COOKIE-NO-SECURE":
			foundNoSecure = true
		case "SS-COOKIE-NO-HTTPONLY":
			foundNoHttpOnly = true
		case "SS-COOKIE-BROAD-DOMAIN":
			foundBroadDomain = true
		}
	}

	if !foundNoSecure {
		t.Errorf("expected SS-COOKIE-NO-SECURE defect to be detected on second cookie")
	}
	if !foundNoHttpOnly {
		t.Errorf("expected SS-COOKIE-NO-HTTPONLY defect to be detected on second cookie")
	}
	if !foundBroadDomain {
		t.Errorf("expected SS-COOKIE-BROAD-DOMAIN defect to be detected on second cookie")
	}
}

// 31. Test Shared Request Budget and Authorization Fail-Closed Invariants
func TestSessionSec_SharedRequestBudgetAndAuthorizationInvariants(t *testing.T) {
	var dispatchedCount int32
	var serverReceivedCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverReceivedCount, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())

	// 1. Invariant: Missing Authorization Record fails-closed with zero network requests
	actxNoAuth := &AssessmentContext{
		AssessmentID:       "asm-inv-no-auth",
		BaseURL:            server.URL,
		SyntheticFixture:   false,
		Authorization:      nil,
		DispatchedRequests: &dispatchedCount,
	}
	_, _, _, errNoAuth := engine.Assess(context.Background(), actxNoAuth)
	if errNoAuth == nil || !strings.Contains(errNoAuth.Error(), "authorization record required") {
		t.Fatalf("expected authorization refusal, got: %v", errNoAuth)
	}
	if dispatchedCount != 0 || serverReceivedCount != 0 {
		t.Fatalf("SECURITY VIOLATION: requests dispatched despite missing authorization: dispatched=%d, server=%d", dispatchedCount, serverReceivedCount)
	}

	// 2. Invariant: Expired Authorization Record fails-closed with zero network requests
	expiredPast := time.Now().UTC().Add(-48 * time.Hour)
	expiredUntil := time.Now().UTC().Add(-24 * time.Hour)
	actxExpired := &AssessmentContext{
		AssessmentID:     "asm-inv-expired",
		BaseURL:          server.URL,
		SyntheticFixture: false,
		Authorization: &auth.AuthorizationRecord{
			ID:                  "auth-expired",
			AuthorizingParty:    "Security Team",
			AuthorizationMethod: "WRITTEN_APPROVAL",
			Status:              "APPROVED",
			ValidFrom:           &expiredPast,
			ValidUntil:          &expiredUntil,
		},
		DispatchedRequests: &dispatchedCount,
	}
	_, _, _, errExpired := engine.Assess(context.Background(), actxExpired)
	if errExpired == nil || !strings.Contains(errExpired.Error(), "authorization is invalid") {
		t.Fatalf("expected authorization invalid refusal, got: %v", errExpired)
	}
	if dispatchedCount != 0 || serverReceivedCount != 0 {
		t.Fatalf("SECURITY VIOLATION: requests dispatched despite expired authorization: dispatched=%d, server=%d", dispatchedCount, serverReceivedCount)
	}

	// 3. Shared Request Budget: Ensure all requests share and strictly obey MaxRequests
	validFrom := time.Now().UTC().Add(-1 * time.Hour)
	validUntil := time.Now().UTC().Add(24 * time.Hour)
	var budgetCounter int32

	actxBudget := &AssessmentContext{
		AssessmentID:     "asm-budget-enforced",
		BaseURL:          server.URL,
		SyntheticFixture: false,
		Authorization: &auth.AuthorizationRecord{
			ID:                  "auth-valid",
			AuthorizingParty:    "Security Team",
			AuthorizationMethod: "WRITTEN_APPROVAL",
			Status:              "APPROVED",
			ValidFrom:           &validFrom,
			ValidUntil:          &validUntil,
		},
		Endpoints: []TargetEndpoint{
			{Method: "POST", Path: "/login", Type: "login"},
			{Method: "GET", Path: "/profile", Type: "protected"},
		},
		MaxRequests:        3, // Strict budget of 3 requests
		DispatchedRequests: &budgetCounter,
		IsAllowed:          func(string) bool { return true },
	}

	// Reset server count before budget test
	atomic.StoreInt32(&serverReceivedCount, 0)

	// Execute assessment with MaxRequests=3
	results, _, _, errBudget := engine.Assess(context.Background(), actxBudget)
	if errBudget != nil {
		t.Fatalf("Assess returned unexpected top-level error: %v", errBudget)
	}

	_ = results
	// Assert that dispatched requests and server received requests strictly equal and never exceed MaxRequests
	if budgetCounter > 3 {
		t.Fatalf("SECURITY VIOLATION: dispatched %d requests, exceeding MaxRequests limit of 3", budgetCounter)
	}
	if serverReceivedCount > 3 {
		t.Fatalf("SECURITY VIOLATION: server received %d requests, exceeding MaxRequests limit of 3", serverReceivedCount)
	}
	if budgetCounter != serverReceivedCount {
		t.Fatalf("mismatch: budgetCounter %d != serverReceivedCount %d", budgetCounter, serverReceivedCount)
	}
	if budgetCounter == 0 {
		t.Fatalf("expected requests to be dispatched up to budget, got 0")
	}
}
