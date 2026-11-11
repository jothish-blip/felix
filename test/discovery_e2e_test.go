package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type controlledDiscoveryApp struct {
	server           *httptest.Server
	logoutHits       int32
	deleteHits       int32
	purgeHits        int32
	restartHits      int32
	checkoutHits     int32
	externalLeakHits int32
}

func setupControlledDiscoveryServer() *controlledDiscoveryApp {
	app := &controlledDiscoveryApp{}

	mux := http.NewServeMux()

	// Root HTML page with navigation, forms, scripts, external links, and destructive links
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>Controlled Attack Surface Target</title>
    <script src="/static/app.js"></script>
    <script src="/static/admin.js"></script>
    <link rel="stylesheet" href="/static/main.css">
</head>
<body>
    <nav>
        <a href="/public/about">About Us</a>
        <a href="/public/about">About Us Duplicate</a>
        <a href="/public/products?category=electronics&sort=asc">Products Catalog</a>
        <a href="/api/profile">User Profile</a>
        <a href="/api/user_a/vault">User A Vault</a>
        <a href="/api/user_b/vault">User B Vault</a>
        <a href="/api/admin/metrics">Admin Metrics</a>
        <a href="/api/private/secret">Forbidden Secret</a>
        <a href="https://external-leak-tracker.com/pixel.gif">External Tracker</a>
        <a href="/auth/logout">Logout</a>
        <a href="/account/delete">Delete Account</a>
        <a href="/api/admin/restart">Restart Server</a>
        <a href="/payment/checkout">Checkout</a>
    </nav>
    <main>
        <form action="/feedback/submit" method="POST">
            <input type="email" name="user_email" required>
            <textarea name="user_feedback"></textarea>
            <button type="submit">Submit Feedback</button>
        </form>
        <form action="/account/purge" method="POST">
            <input type="text" name="confirmation">
            <button type="submit">Purge Everything</button>
        </form>
    </main>
</body>
</html>`)
	})

	// Public Page 1
	mux.HandleFunc("/public/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><h1>About Page</h1><a href="/public/contact">Contact Us</a></body></html>`)
	})

	// Public Page 2
	mux.HandleFunc("/public/contact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><h1>Contact Information</h1></body></html>`)
	})

	// Products Catalog with Query Parameters
	mux.HandleFunc("/public/products", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		cat := r.URL.Query().Get("category")
		fmt.Fprintf(w, `<html><body><h1>Products in category: %s</h1></body></html>`, cat)
	})

	// Form Submission Target (Negative Control: safe form action)
	mux.HandleFunc("/feedback/submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"feedback_received"}`)
	})

	// Static JS Bundle 1: App bundle with embedded route literals
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
		(function() {
			function loadUsers() {
				return fetch("/api/v1/users");
			}
			function loadOrder(id) {
				return fetch("/api/v1/orders/" + id);
			}
			var healthCheck = "/api/v1/health";
		})();`)
	})

	// Static JS Bundle 2: Admin bundle with embedded route literals
	mux.HandleFunc("/static/admin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
		(function() {
			function getSystemConfig() {
				return fetch("/api/admin/config");
			}
			function restartServer() {
				return axios.post("/api/admin/restart", { force: true });
			}
			function runCheckout() {
				return axios.post("/payment/checkout", { amount: 100 });
			}
		})();`)
	})

	// Stylesheet
	mux.HandleFunc("/static/main.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, `body { font-family: sans-serif; }`)
	})

	// Authenticated Profile Endpoint
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if authHdr == "Bearer test_user_a_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"username":"alice","role":"user_a"}`)
			return
		}
		if authHdr == "Bearer test_user_b_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"username":"bob","role":"user_b"}`)
			return
		}
		if authHdr == "Bearer test_admin_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"username":"admin","role":"administrator"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"authentication_required"}`)
	})

	// User A Private Endpoint (200 for User A, 401 for Anon, 403 for User B and Admin)
	mux.HandleFunc("/api/user_a/vault", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if authHdr == "Bearer test_user_a_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"owner":"user_a","data":"vault_a_secret"}`)
			return
		}
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthenticated"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden_user_a_only"}`)
	})

	// User B Private Endpoint (200 for User B, 401 for Anon, 403 for User A and Admin)
	mux.HandleFunc("/api/user_b/vault", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if authHdr == "Bearer test_user_b_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"owner":"user_b","data":"vault_b_secret"}`)
			return
		}
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthenticated"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden_user_b_only"}`)
	})

	// Admin-Only Endpoint (200 for Admin, 401 for Anon, 403 for User A and User B)
	mux.HandleFunc("/api/admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if authHdr == "Bearer test_admin_token" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"cpu_percent":42,"memory_mb":1024}`)
			return
		}
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthenticated"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"admin_role_required"}`)
	})

	// Inaccessible endpoint (403 for all)
	mux.HandleFunc("/api/private/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden_classification"}`)
	})

	// Destructive endpoints: MUST NOT BE CALLED
	mux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&app.logoutHits, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"action":"logged_out"}`)
	})
	mux.HandleFunc("/account/delete", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&app.deleteHits, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"action":"account_deleted"}`)
	})
	mux.HandleFunc("/account/purge", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&app.purgeHits, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"action":"purged"}`)
	})
	mux.HandleFunc("/api/admin/restart", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&app.restartHits, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"action":"restarted"}`)
	})
	mux.HandleFunc("/payment/checkout", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&app.checkoutHits, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"action":"checked_out"}`)
	})

	app.server = httptest.NewServer(mux)
	return app
}

// TestE2E_AttackSurfaceDiscovery_UnifiedCLI executes `felix assess` and validates
// end-to-end active crawling, JS bundle extraction, four-identity visibility, and safety boundaries.
func TestE2E_AttackSurfaceDiscovery_UnifiedCLI(t *testing.T) {
	app := setupControlledDiscoveryServer()
	defer app.server.Close()

	targetURL := app.server.URL
	tmpOut := t.TempDir()

	// Execute felix assess with User A, User B, and Admin credentials (4 identities with Anonymous)
	out, exitCode := runFelix(t, "assess",
		"--target", targetURL,
		"--profile", "quick",
		"--output", tmpOut,
		"--auth-user-a", "test_user_a_token",
		"--auth-user-b", "test_user_b_token",
		"--auth-admin", "test_admin_token",
		"--auth-confirm",
		"--allow-loopback",
		"--crawl-depth", "3",
		"--crawl-max-pages", "20",
		"--crawl-max-requests", "50",
	)

	if exitCode != 0 && exitCode != 1 {
		t.Fatalf("felix assess failed with unexpected exit code %d. Output:\n%s", exitCode, out)
	}

	// 1. Mandatory Safety Assertion: Destructive endpoints MUST NOT be visited
	if app.logoutHits > 0 {
		t.Fatalf("CRITICAL SAFETY BREACH: /auth/logout was requested %d times during crawling", app.logoutHits)
	}
	if app.deleteHits > 0 {
		t.Fatalf("CRITICAL SAFETY BREACH: /account/delete was requested %d times during crawling", app.deleteHits)
	}
	if app.purgeHits > 0 {
		t.Fatalf("CRITICAL SAFETY BREACH: /account/purge was requested %d times during crawling", app.purgeHits)
	}
	if app.restartHits > 0 {
		t.Fatalf("CRITICAL SAFETY BREACH: /api/admin/restart was requested %d times during crawling", app.restartHits)
	}
	if app.checkoutHits > 0 {
		t.Fatalf("CRITICAL SAFETY BREACH: /payment/checkout was requested %d times during crawling", app.checkoutHits)
	}

	// 2. Read and verify discovery_summary.json deliverable
	discSummaryFile := filepath.Join(tmpOut, "discovery_summary.json")
	discBytes, err := os.ReadFile(discSummaryFile)
	if err != nil {
		t.Fatalf("Failed to read discovery_summary.json: %v", err)
	}

	var discData struct {
		Summary struct {
			TotalPagesDiscovered       int `json:"total_pages_discovered"`
			TotalConfirmedEndpoints    int `json:"total_confirmed_endpoints"`
			TotalEndpointCandidates    int `json:"total_endpoint_candidates"`
			TotalJavaScriptBundles     int `json:"total_javascript_bundles"`
			TotalFormsAndInputs        int `json:"total_forms_and_inputs"`
			TotalStaticAssets          int `json:"total_static_assets"`
			TotalInaccessibleResources int `json:"total_inaccessible_resources"`
			TotalExcludedResources     int `json:"total_excluded_resources"`
			TotalRequestsMade          int `json:"total_requests_made"`
		} `json:"summary"`
		VisibilityMatrix struct {
			Identities []string `json:"identities"`
			Endpoints  map[string]map[string]struct {
				Visible        bool   `json:"visible"`
				StatusCode     int    `json:"status_code"`
				StatusText     string `json:"status_text"`
				Classification string `json:"classification"`
			} `json:"endpoints"`
		} `json:"visibility_matrix"`
		CoverageGaps []struct {
			Type            string `json:"type"`
			Resource        string `json:"resource"`
			Reason          string `json:"reason"`
			IdentityContext string `json:"identity_context"`
		} `json:"coverage_gaps"`
	}

	if err := json.Unmarshal(discBytes, &discData); err != nil {
		t.Fatalf("Failed to parse discovery_summary.json: %v", err)
	}

	// Ground Truth Verification:
	// Total pages discovered: at least 3 (/, /public/about, /public/contact)
	if discData.Summary.TotalPagesDiscovered < 3 {
		t.Errorf("Expected TotalPagesDiscovered >= 3, got %d", discData.Summary.TotalPagesDiscovered)
	}

	// JavaScript bundles: exactly 2 (/static/app.js, /static/admin.js)
	if discData.Summary.TotalJavaScriptBundles < 2 {
		t.Errorf("Expected TotalJavaScriptBundles >= 2, got %d", discData.Summary.TotalJavaScriptBundles)
	}

	// Endpoint candidates from JS: at least 3 (/api/v1/users, /api/v1/health, /api/admin/config)
	if discData.Summary.TotalEndpointCandidates < 3 {
		t.Errorf("Expected TotalEndpointCandidates >= 3, got %d", discData.Summary.TotalEndpointCandidates)
	}

	// Forms & inputs: at least 1 (/feedback/submit)
	if discData.Summary.TotalFormsAndInputs < 1 {
		t.Errorf("Expected TotalFormsAndInputs >= 1, got %d", discData.Summary.TotalFormsAndInputs)
	}

	// Excluded resources: at least 2 (/auth/logout, /account/delete)
	if discData.Summary.TotalExcludedResources < 2 {
		t.Errorf("Expected TotalExcludedResources >= 2, got %d", discData.Summary.TotalExcludedResources)
	}

	// Inaccessible resources: at least 1 (/api/private/secret)
	if discData.Summary.TotalInaccessibleResources < 1 {
		t.Errorf("Expected TotalInaccessibleResources >= 1, got %d", discData.Summary.TotalInaccessibleResources)
	}

	// 3. Verify Identity Visibility Matrix across all 4 identities
	matrix := discData.VisibilityMatrix
	if len(matrix.Identities) < 4 {
		t.Errorf("Expected at least 4 identities in matrix (ANONYMOUS, USER_A, USER_B, ADMIN), got %v", matrix.Identities)
	}

	// Check /api/user_a/vault visibility across identities
	vaultAObs, hasVaultA := matrix.Endpoints["GET /api/user_a/vault"]
	if !hasVaultA {
		t.Errorf("Expected GET /api/user_a/vault in visibility matrix")
	} else {
		if anonObs, ok := vaultAObs["ANONYMOUS"]; ok {
			if anonObs.StatusCode != 401 {
				t.Errorf("Expected /api/user_a/vault for ANONYMOUS to be 401, got %d", anonObs.StatusCode)
			}
		}
		if userAObs, ok := vaultAObs["USER_A"]; ok {
			if userAObs.StatusCode != 200 {
				t.Errorf("Expected /api/user_a/vault for USER_A to be 200, got %d", userAObs.StatusCode)
			}
		}
		if userBObs, ok := vaultAObs["USER_B"]; ok {
			if userBObs.StatusCode != 403 {
				t.Errorf("Expected /api/user_a/vault for USER_B to be 403, got %d", userBObs.StatusCode)
			}
		}
	}

	// Check /api/user_b/vault visibility across identities
	vaultBObs, hasVaultB := matrix.Endpoints["GET /api/user_b/vault"]
	if !hasVaultB {
		t.Errorf("Expected GET /api/user_b/vault in visibility matrix")
	} else {
		if anonObs, ok := vaultBObs["ANONYMOUS"]; ok {
			if anonObs.StatusCode != 401 {
				t.Errorf("Expected /api/user_b/vault for ANONYMOUS to be 401, got %d", anonObs.StatusCode)
			}
		}
		if userAObs, ok := vaultBObs["USER_A"]; ok {
			if userAObs.StatusCode != 403 {
				t.Errorf("Expected /api/user_b/vault for USER_A to be 403, got %d", userAObs.StatusCode)
			}
		}
		if userBObs, ok := vaultBObs["USER_B"]; ok {
			if userBObs.StatusCode != 200 {
				t.Errorf("Expected /api/user_b/vault for USER_B to be 200, got %d", userBObs.StatusCode)
			}
		}
	}

	// Check /api/admin/metrics visibility across identities
	adminObs, hasAdmin := matrix.Endpoints["GET /api/admin/metrics"]
	if !hasAdmin {
		t.Errorf("Expected GET /api/admin/metrics in visibility matrix")
	} else {
		if anonObs, ok := adminObs["ANONYMOUS"]; ok {
			if anonObs.StatusCode != 401 {
				t.Errorf("Expected /api/admin/metrics for ANONYMOUS to be 401, got %d", anonObs.StatusCode)
			}
		}
		if userAObs, ok := adminObs["USER_A"]; ok {
			if userAObs.StatusCode != 403 {
				t.Errorf("Expected /api/admin/metrics for USER_A to be 403, got %d", userAObs.StatusCode)
			}
		}
		if adminRealObs, ok := adminObs["ADMIN"]; ok {
			if adminRealObs.StatusCode != 200 {
				t.Errorf("Expected /api/admin/metrics for ADMIN to be 200, got %d", adminRealObs.StatusCode)
			}
		}
	}

	// 4. Verify Coverage Gaps
	hasAuthGap := false
	hasSafetyGap := false
	for _, gap := range discData.CoverageGaps {
		if gap.Type == "AUTH_BLOCKED" {
			hasAuthGap = true
		}
		if gap.Type == "SAFETY_EXCLUSION" {
			hasSafetyGap = true
		}
	}
	if !hasAuthGap {
		t.Errorf("Expected AUTH_BLOCKED coverage gap to be recorded")
	}
	if !hasSafetyGap {
		t.Errorf("Expected SAFETY_EXCLUSION coverage gap to be recorded for destructive actions")
	}

	// 5. Verify CLI Terminal Output contains the Attack Surface Discovery Summary
	if !strings.Contains(out, "ATTACK SURFACE DISCOVERY SUMMARY") {
		t.Errorf("CLI output did not contain ATTACK SURFACE DISCOVERY SUMMARY section")
	}
	if !strings.Contains(out, "Identity Visibility Matrix:") {
		t.Errorf("CLI output did not contain Identity Visibility Matrix")
	}
}

// TestE2E_AttackSurfaceDiscovery_UnconfiguredIdentities verifies that unconfigured identities
// are explicitly marked NOT_CONFIGURED rather than simulated or falsely reported.
func TestE2E_AttackSurfaceDiscovery_UnconfiguredIdentities(t *testing.T) {
	app := setupControlledDiscoveryServer()
	defer app.server.Close()

	targetURL := app.server.URL
	tmpOut := t.TempDir()

	// Execute felix assess with only User A configured (USER_B and ADMIN omitted)
	out, exitCode := runFelix(t, "assess",
		"--target", targetURL,
		"--profile", "quick",
		"--output", tmpOut,
		"--auth-user-a", "test_user_a_token",
		"--auth-confirm",
		"--allow-loopback",
		"--crawl-depth", "2",
		"--crawl-max-pages", "10",
		"--crawl-max-requests", "30",
	)

	if exitCode != 0 && exitCode != 1 {
		t.Fatalf("felix assess failed with unexpected exit code %d. Output:\n%s", exitCode, out)
	}

	discSummaryFile := filepath.Join(tmpOut, "discovery_summary.json")
	discBytes, err := os.ReadFile(discSummaryFile)
	if err != nil {
		t.Fatalf("Failed to read discovery_summary.json: %v", err)
	}

	var discData struct {
		VisibilityMatrix struct {
			Identities []string `json:"identities"`
			Endpoints  map[string]map[string]struct {
				Visible        bool   `json:"visible"`
				StatusCode     int    `json:"status_code"`
				StatusText     string `json:"status_text"`
				Classification string `json:"classification"`
			} `json:"endpoints"`
		} `json:"visibility_matrix"`
	}

	if err := json.Unmarshal(discBytes, &discData); err != nil {
		t.Fatalf("Failed to parse discovery_summary.json: %v", err)
	}

	matrix := discData.VisibilityMatrix
	// Check that unconfigured identities are explicitly marked NOT_CONFIGURED
	for rKey, obsMap := range matrix.Endpoints {
		userBObs, hasB := obsMap["USER_B"]
		if !hasB || userBObs.StatusText != "NOT_CONFIGURED" {
			t.Errorf("route %s under unconfigured USER_B expected status NOT_CONFIGURED, got %+v", rKey, userBObs)
		}
		adminObs, hasAdmin := obsMap["ADMIN"]
		if !hasAdmin || adminObs.StatusText != "NOT_CONFIGURED" {
			t.Errorf("route %s under unconfigured ADMIN expected status NOT_CONFIGURED, got %+v", rKey, adminObs)
		}
	}
}
