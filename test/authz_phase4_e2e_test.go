package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"felix/pkg/report"
)

const (
	p4UserAToken  = "tok_alice_phase4_secret_987654"
	p4UserBToken  = "tok_bob_phase4_secret_123456"
	p4AdminToken  = "tok_admin_phase4_secret_654321"
	p4UserACookie = "cookie_alice_secret_987654"
	p4UserBCookie = "cookie_bob_secret_123456"
	p4AdminCookie = "cookie_admin_secret_654321"
	p4APISecret   = "sk_live_phase4_canary_abcdef123456"
)

type phase4FixtureApp struct {
	server *httptest.Server

	mu            sync.Mutex
	profileRole   string
	profileAdmin  bool
	bleedErrors   []string
	seenAuthUsers map[string]bool

	// Destructive endpoints hit counters (MUST stay 0 in ALL tests)
	deleteOrderHits int32
	adminWipeHits   int32
	passwordHits    int32
	billingPayHits  int32

	// Non-destructive write endpoint hit counters
	profileWriteHits int32
	prefWriteHits    int32
}

func (a *phase4FixtureApp) identifyRequest(r *http.Request) string {
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	cookieHdr := r.Header.Get("Cookie")

	matched := make([]string, 0, 2)
	if authHdr == "Bearer "+p4UserAToken || strings.Contains(cookieHdr, "felix_sid="+p4UserACookie) {
		matched = append(matched, "USER_A")
	}
	if authHdr == "Bearer "+p4UserBToken || strings.Contains(cookieHdr, "felix_sid="+p4UserBCookie) {
		matched = append(matched, "USER_B")
	}
	if authHdr == "Bearer "+p4AdminToken || strings.Contains(cookieHdr, "felix_sid="+p4AdminCookie) {
		matched = append(matched, "ADMIN")
	}

	if len(matched) > 1 {
		a.mu.Lock()
		a.bleedErrors = append(a.bleedErrors, fmt.Sprintf("cross-identity credential bleed on %s %s: %v", r.Method, r.URL.Path, matched))
		a.mu.Unlock()
	}
	if authHdr != "" && cookieHdr != "" && strings.Contains(cookieHdr, "felix_sid=") {
		// Ensure cookie and bearer match the same persona if both ever appear
		if len(matched) != 1 {
			a.mu.Lock()
			a.bleedErrors = append(a.bleedErrors, fmt.Sprintf("mismatched bearer+cookie on %s %s", r.Method, r.URL.Path))
			a.mu.Unlock()
		}
	}

	if len(matched) == 0 {
		return "ANONYMOUS"
	}
	a.mu.Lock()
	a.seenAuthUsers[matched[0]] = true
	a.mu.Unlock()
	return matched[0]
}

type phase4FixtureOpts struct {
	fixtureHeader      bool
	prodMarkerHeader   bool
	failProfileRestore bool
}

func setupPhase4FixtureApp() *phase4FixtureApp {
	return setupPhase4FixtureAppWithOpts(phase4FixtureOpts{
		fixtureHeader: true,
	})
}

func setupPhase4FixtureAppWithOpts(opts phase4FixtureOpts) *phase4FixtureApp {
	app := &phase4FixtureApp{
		profileRole:   "user",
		profileAdmin:  false,
		seenAuthUsers: make(map[string]bool),
	}

	mux := http.NewServeMux()
	applyFixtureHeaders := func(w http.ResponseWriter) {
		if opts.fixtureHeader {
			w.Header().Set("X-Felix-Synthetic-Fixture", "true")
		}
		if opts.prodMarkerHeader {
			w.Header().Set("X-Environment", "production")
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = app.identifyRequest(r)
		applyFixtureHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Phase4 Ground Truth App</title><script src="/app.js"></script></head>
<body>
  <nav>
    <a href="/health">Health</a>
    <a href="/api/public/catalog">Catalog</a>
    <a href="/openapi.json">OpenAPI</a>
    <a href="/api/me">Me</a>
    <a href="/api/dashboard">Dashboard</a>
    <a href="/api/directory">Directory</a>
    <a href="/api/team">Team</a>
    <a href="/api/profile">Profile</a>
    <a href="/api/preferences">Preferences</a>
  </nav>
  <form action="/api/profile" method="put">
    <input type="text" name="display_name" value="Alice"/>
  </form>
</body>
</html>`)
	})

	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
window.APP_ROUTES = [
  "/api/orders/101",
  "/api/orders/102",
  "/api/documents/201",
  "/api/admin/audit",
  "/api/admin/metrics",
  "/api/admin/panel",
  "/api/admin/logs",
  "/api/internal/ping"
];`)
	})

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "components": {
    "schemas": {
      "ProfileUpdate": {
        "type": "object",
        "properties": {
          "display_name": {"type": "string"},
          "role": {"type": "string", "readOnly": true, "x-admin-only": true},
          "is_admin": {"type": "boolean", "readOnly": true, "x-admin-only": true}
        }
      },
      "PrefUpdate": {
        "type": "object",
        "properties": {
          "plan_tier": {"type": "string", "readOnly": true}
        }
      }
    }
  },
  "paths": {
    "/api/orders/{order_id}": {
      "get": {"summary": "Get order", "security": [{"bearerAuth": []}]},
      "delete": {"summary": "Delete order"}
    },
    "/api/documents/{doc_id}": {
      "get": {"summary": "Get document", "security": [{"bearerAuth": []}]}
    },
    "/api/admin/audit": {
      "get": {"summary": "Admin audit trail", "x-roles": ["admin"], "tags": ["admin"]}
    },
    "/api/admin/metrics": {
      "get": {"summary": "Admin metrics", "x-roles": ["admin"], "tags": ["admin"]}
    },
    "/api/admin/panel": {
      "get": {"summary": "Admin panel", "x-roles": ["admin"], "tags": ["admin"]}
    },
    "/api/admin/logs": {
      "get": {"summary": "Admin logs", "x-roles": ["admin"], "tags": ["admin"]}
    },
    "/api/admin/wipe": {
      "post": {"summary": "Wipe all data", "x-roles": ["admin"]}
    },
    "/api/account/password": {
      "post": {"summary": "Change password"}
    },
    "/api/billing/payment": {
      "post": {"summary": "Submit payment"}
    },
    "/api/profile": {
      "get": {"summary": "Read profile"},
      "put": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProfileUpdate"}}}}}
    },
    "/api/preferences": {
      "get": {"summary": "Read preferences"},
      "patch": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/PrefUpdate"}}}}}
    }
  }
}`)
	})

	// Public benign controls
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		applyFixtureHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","version":"1.0.0"}`))
	})
	mux.HandleFunc("/api/public/catalog", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"name":"Starter Plan","version":"2026.1","items":[{"id":1,"title":"Public Guide"}]}`))
	})
	mux.HandleFunc("/api/internal/ping", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// Self-anchor endpoint
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		switch ident {
		case "USER_A":
			_, _ = w.Write([]byte(`{"id":"u_alice","username":"alice","email":"alice@phase4.local"}`))
		case "USER_B":
			_, _ = w.Write([]byte(`{"id":"u_bob","username":"bob","email":"bob@phase4.local"}`))
		case "ADMIN":
			_, _ = w.Write([]byte(`{"id":"u_admin","username":"admin","email":"admin@phase4.local"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	})

	// Per-identity dashboard advertising owned object links
	mux.HandleFunc("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch ident {
		case "USER_A":
			fmt.Fprint(w, `<html><body><a href="/api/orders/101">My Order</a><a href="/api/documents/201">My Doc</a></body></html>`)
		case "USER_B":
			fmt.Fprint(w, `<html><body><a href="/api/orders/102">My Order</a><a href="/api/documents/202">My Doc</a></body></html>`)
		case "ADMIN":
			fmt.Fprint(w, `<html><body><a href="/api/admin/audit">Audit</a><a href="/api/admin/metrics">Metrics</a><a href="/api/admin/panel">Panel</a><a href="/api/admin/logs">Logs</a><a href="/api/admin/wipe">Wipe</a><a href="/api/account/password">Password</a><a href="/api/billing/payment">Billing</a></body></html>`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `<html><body>Sign in</body></html>`)
		}
	})

	// BOLA vulnerable endpoint + DELETE destructive guard
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		id = strings.TrimSuffix(id, "/delete")
		if r.Method == http.MethodDelete || strings.HasSuffix(r.URL.Path, "/delete") {
			atomic.AddInt32(&app.deleteOrderHits, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth_required"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch id {
		case "101":
			_, _ = w.Write([]byte(`{"order_id":"101","owner_id":"u_alice","username":"alice","private_note":"alice-confidential-wire-transfer-101","total":"1500.00"}`))
		case "102":
			_, _ = w.Write([]byte(`{"order_id":"102","owner_id":"u_bob","username":"bob","private_note":"bob-confidential-contract-102","total":"2500.00"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
		}
	})

	// BOLA negative control: strictly enforces owner check
	mux.HandleFunc("/api/documents/", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/documents/")
		w.Header().Set("Content-Type", "application/json")
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth_required"}`))
			return
		}
		switch {
		case id == "201" && (ident == "USER_A" || ident == "ADMIN"):
			_, _ = w.Write([]byte(`{"doc_id":"201","owner_id":"u_alice","private_note":"alice-tax-doc-201"}`))
		case id == "202" && (ident == "USER_B" || ident == "ADMIN"):
			_, _ = w.Write([]byte(`{"doc_id":"202","owner_id":"u_bob","private_note":"bob-tax-doc-202"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden_owner_mismatch"}`))
		}
	})

	// BFLA vulnerable endpoint: missing admin check for lower roles
	mux.HandleFunc("/api/admin/audit", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		_, _ = w.Write([]byte(`{"audit_events":["admin_role_grant","api_key_issued"],"admin_report":true,"privileged_records":14}`))
	})

	// BFLA negative control: strict 403 for non-admin
	mux.HandleFunc("/api/admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ADMIN" {
			_, _ = w.Write([]byte(`{"cluster_cpu":"19%","active_admins":2}`))
			return
		}
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"admin_required"}`))
	})

	// BFLA Trap 1: HTTP 200 HTML login page for lower-privilege users
	mux.HandleFunc("/api/admin/panel", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		if ident == "ADMIN" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"panel_status":"admin_unlocked","root_nodes":4}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Login Required</h1><form action="/login"><input type="password"/></form></body></html>`))
	})

	// BFLA Trap 2: HTTP 200 JSON error body for lower-privilege users
	mux.HandleFunc("/api/admin/logs", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ADMIN" {
			_, _ = w.Write([]byte(`{"system_logs":["service started"],"admin_view":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":"forbidden","authorized":false,"message":"insufficient privileges"}`))
	})

	// Destructive endpoints (must NEVER be invoked)
	mux.HandleFunc("/api/admin/wipe", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		atomic.AddInt32(&app.adminWipeHits, 1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/account/password", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		atomic.AddInt32(&app.passwordHits, 1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/billing/payment", func(w http.ResponseWriter, r *http.Request) {
		_ = app.identifyRequest(r)
		atomic.AddInt32(&app.billingPayHits, 1)
		w.WriteHeader(http.StatusOK)
	})

	// BOPLA vulnerable exposure: leaks internal_notes, unmasked ssn, and secret key
	mux.HandleFunc("/api/directory", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             7,
			"version":        "1.0",
			"internal_notes": "vip-escalation-override-enabled",
			"ssn":            "123-45-6789",
			"api_secret":     p4APISecret,
		})
	})

	// BOPLA negative control: cleanly omits salary and masks SSN for non-admin
	mux.HandleFunc("/api/team", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ADMIN" {
			_, _ = w.Write([]byte(`{"member":"alice","salary":185000,"ssn":"123-45-6789"}`))
			return
		}
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		_, _ = w.Write([]byte(`{"member":"alice","ssn":"***-**-6789"}`))
	})

	// BOPLA reversible mass assignment on role / is_admin
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		if r.Method == http.MethodGet {
			app.mu.Lock()
			role := app.profileRole
			isAdm := app.profileAdmin
			app.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":           42,
				"display_name": "Alice",
				"role":         role,
				"is_admin":     isAdm,
			})
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			atomic.AddInt32(&app.profileWriteHits, 1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if opts.failProfileRestore {
				if rv, ok := body["role"].(string); ok && rv == "user" {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"forced cleanup failure"}`))
					return
				}
			}
			app.mu.Lock()
			if rv, ok := body["role"].(string); ok && rv != "" {
				app.profileRole = rv
			}
			if av, ok := body["is_admin"].(bool); ok {
				app.profileAdmin = av
			}
			role := app.profileRole
			isAdm := app.profileAdmin
			app.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":           42,
				"display_name": "Alice",
				"role":         role,
				"is_admin":     isAdm,
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// BOPLA echoed-only non-persisted trap
	mux.HandleFunc("/api/preferences", func(w http.ResponseWriter, r *http.Request) {
		ident := app.identifyRequest(r)
		w.Header().Set("Content-Type", "application/json")
		if ident == "ANONYMOUS" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"theme":"light","plan_tier":"free"}`))
			return
		}
		if r.Method == http.MethodPatch || r.Method == http.MethodPut {
			atomic.AddInt32(&app.prefWriteHits, 1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	app.server = httptest.NewServer(mux)
	return app
}

func assertNoDestructiveHits(t *testing.T, app *phase4FixtureApp) {
	t.Helper()
	if hits := atomic.LoadInt32(&app.deleteOrderHits); hits > 0 {
		t.Fatalf("SAFETY VIOLATION: DELETE /api/orders hit %d times", hits)
	}
	if hits := atomic.LoadInt32(&app.adminWipeHits); hits > 0 {
		t.Fatalf("SAFETY VIOLATION: POST /api/admin/wipe hit %d times", hits)
	}
	if hits := atomic.LoadInt32(&app.passwordHits); hits > 0 {
		t.Fatalf("SAFETY VIOLATION: POST /api/account/password hit %d times", hits)
	}
	if hits := atomic.LoadInt32(&app.billingPayHits); hits > 0 {
		t.Fatalf("SAFETY VIOLATION: POST /api/billing/payment hit %d times", hits)
	}
}

func assertNoBleedErrors(t *testing.T, app *phase4FixtureApp) {
	t.Helper()
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(app.bleedErrors) > 0 {
		t.Fatalf("credential bleed detected across requests: %s", strings.Join(app.bleedErrors, "; "))
	}
}

func assertNoSecretLeakInOutputs(t *testing.T, dir, stdout string, secretsList []string) {
	t.Helper()
	for _, sec := range secretsList {
		if sec == "" {
			continue
		}
		if strings.Contains(stdout, sec) {
			t.Fatalf("secret %q leaked in stdout output", sec)
		}
		entries, _ := os.ReadDir(dir)
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(b), sec) {
				t.Fatalf("secret %q leaked in deliverable %s", sec, ent.Name())
			}
		}
	}
}

func readAuthzSummaryFile(t *testing.T, outDir string) report.AuthorizationReportSummary {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(outDir, "authorization_summary.json"))
	if err != nil {
		t.Fatalf("failed reading authorization_summary.json: %v", err)
	}
	var summary report.AuthorizationReportSummary
	if err := json.Unmarshal(b, &summary); err != nil {
		t.Fatalf("failed parsing authorization_summary.json: %v", err)
	}
	return summary
}

func readReportJSONFile(t *testing.T, outDir string) report.Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(outDir, "assessment_report.json"))
	if err != nil {
		t.Fatalf("failed reading assessment_report.json: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("failed parsing assessment_report.json: %v", err)
	}
	return rep
}

func TestPhase4E2E_FullGroundTruth_SafeDefault(t *testing.T) {
	app := setupPhase4FixtureApp()
	defer app.server.Close()

	outDir := t.TempDir()
	out, code := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "full",
		"--output", outDir,
		"--auth-user-a", p4UserAToken,
		"--auth-user-b", p4UserBToken,
		"--auth-admin", p4AdminToken,
		"--auth-confirm",
		"--allow-loopback",
		"--crawl-depth", "3",
		"--crawl-max-pages", "40",
		"--crawl-max-requests", "120",
		"--authz-max-requests", "200",
		"--authz-max-per-identity", "80",
	)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected felix assess exit code %d:\n%s", code, out)
	}

	assertNoDestructiveHits(t, app)
	assertNoBleedErrors(t, app)
	if w := atomic.LoadInt32(&app.profileWriteHits); w > 0 {
		t.Fatalf("expected zero state-changing /api/profile writes in default safe mode, got %d", w)
	}
	if w := atomic.LoadInt32(&app.prefWriteHits); w > 0 {
		t.Fatalf("expected zero state-changing /api/preferences writes in default safe mode, got %d", w)
	}

	assertNoSecretLeakInOutputs(t, outDir, out, []string{p4UserAToken, p4UserBToken, p4AdminToken, p4APISecret})

	authzSum := readAuthzSummaryFile(t, outDir)
	if authzSum.RequestsSent == 0 {
		t.Fatalf("expected non-zero authz requests sent, got 0; summary=%+v", authzSum)
	}
	if authzSum.BOLA == nil || authzSum.BOLA.VerifiedCount == 0 {
		t.Fatalf("expected verified BOLA finding on /api/orders/{order_id}, got BOLA=%+v\nOutput:\n%s", authzSum.BOLA, out)
	}
	if authzSum.BFLA == nil || authzSum.BFLA.VerifiedCount == 0 {
		t.Fatalf("expected verified BFLA finding on /api/admin/audit, got BFLA=%+v", authzSum.BFLA)
	}
	if authzSum.BOPLA == nil || authzSum.BOPLA.VerifiedCount == 0 {
		t.Fatalf("expected verified read BOPLA finding on /api/directory, got BOPLA=%+v", authzSum.BOPLA)
	}
	if authzSum.BOPLA.SkippedCount == 0 || authzSum.BOPLA.ModificationTests != 0 {
		t.Fatalf("expected BOPLA modification checks skipped in safe default mode, got %+v", authzSum.BOPLA)
	}
	if authzSum.FixtureVerification == nil || authzSum.FixtureVerification.Method != "NOT_REQUESTED" {
		t.Fatalf("expected FixtureVerification NOT_REQUESTED in safe default mode, got %+v", authzSum.FixtureVerification)
	}
	qc := authzSum.QuantitativeCoverage
	if qc.EndpointsObserved == 0 || qc.TotalChecksPlanned == 0 || qc.TotalChecksExecuted == 0 || qc.ExecutionCoveragePct <= 0 || qc.DeterminativeOutcomePct <= 0 {
		t.Fatalf("expected non-zero quantitative coverage metrics, got %+v", qc)
	}
	if qc.ExcludedDestructiveCount < 4 {
		t.Fatalf("expected at least 4 excluded destructive endpoints tracked, got %d", qc.ExcludedDestructiveCount)
	}
	if !strings.Contains(out, "Determinative:") {
		t.Fatalf("expected quantitative summary metrics in stdout:\n%s", out)
	}
	if sumBytes, err := json.Marshal(authzSum); err == nil {
		t.Logf("SAFE_DEFAULT_AUTHZ_SUMMARY=%s", string(sumBytes))
	}

	// Verify Ground Truth True Positives AND Negative Controls across findings
	rep := readReportJSONFile(t, outDir)
	var sawOrdersBOLA, sawAuditBFLA, sawDirectoryBOPLA bool
	for _, f := range rep.Findings {
		lowCat := strings.ToLower(f.Category)
		isAuthzFinding := strings.Contains(lowCat, "bola") || strings.Contains(lowCat, "bfla") || strings.Contains(lowCat, "bopla") || strings.Contains(lowCat, "api1:") || strings.Contains(lowCat, "api3:") || strings.Contains(lowCat, "api5:")
		if !isAuthzFinding {
			continue
		}
		if strings.Contains(f.Endpoint, "/api/orders") {
			sawOrdersBOLA = true
		}
		if strings.Contains(f.Endpoint, "/api/admin/audit") {
			sawAuditBFLA = true
		}
		if strings.Contains(f.Endpoint, "/api/directory") {
			sawDirectoryBOPLA = true
		}
		// Ensure zero verified authz findings on negative controls or traps
		state := strings.ToUpper(f.EvidenceDetails.Details["verification_state"])
		if state == "VERIFIED" {
			for _, badEp := range []string{"/api/documents", "/api/admin/metrics", "/api/admin/panel", "/api/admin/logs", "/api/internal/ping", "/api/team", "/health", "/api/public/catalog", "/api/preferences"} {
				if strings.Contains(f.Endpoint, badEp) {
					t.Fatalf("FALSE POSITIVE: verified authz finding triggered on negative control %s (%+v)", badEp, f)
				}
			}
		}
	}
	if !sawOrdersBOLA || !sawAuditBFLA || !sawDirectoryBOPLA {
		t.Fatalf("missing ground truth verified findings: orders=%v audit=%v directory=%v", sawOrdersBOLA, sawAuditBFLA, sawDirectoryBOPLA)
	}

	// HTML report must render authorization assessment breakdown
	htmlBytes, err := os.ReadFile(filepath.Join(outDir, "assessment_report.html"))
	if err != nil {
		t.Fatalf("failed reading assessment_report.html: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "authorization-assessment") || !strings.Contains(htmlStr, "Authorization") {
		t.Fatalf("HTML report missing Authorization Assessment section")
	}
}

func TestPhase4E2E_OptedInSyntheticFixture_ReversibleMassAssignment(t *testing.T) {
	app := setupPhase4FixtureApp()
	defer app.server.Close()

	outDir := t.TempDir()
	out, code := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "custom",
		"--modules", "recon,bopla,authz",
		"--output", outDir,
		"--auth-user-a", p4UserAToken,
		"--auth-user-b", p4UserBToken,
		"--auth-admin", p4AdminToken,
		"--allow-state-changing",
		"--synthetic-fixture",
		"--auth-confirm",
		"--allow-loopback",
		"--crawl-depth", "3",
		"--crawl-max-pages", "40",
		"--crawl-max-requests", "120",
	)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit code %d:\n%s", code, out)
	}

	assertNoDestructiveHits(t, app)
	assertNoBleedErrors(t, app)
	if atomic.LoadInt32(&app.profileWriteHits) == 0 {
		t.Fatalf("expected state-changing probe against /api/profile with opt-in flags")
	}

	// Verify reversible cleanup restored server state
	app.mu.Lock()
	restoredRole := app.profileRole
	restoredAdmin := app.profileAdmin
	app.mu.Unlock()
	if restoredRole != "user" || restoredAdmin {
		t.Fatalf("expected reversible mass assignment cleanup to restore role=user, is_admin=false; got role=%q is_admin=%v", restoredRole, restoredAdmin)
	}

	optAuthzSum := readAuthzSummaryFile(t, outDir)
	if optAuthzSum.FixtureVerification == nil || !optAuthzSum.FixtureVerification.Verified || optAuthzSum.FixtureVerification.Method != "HEADER_ATTESTATION" {
		t.Fatalf("expected HEADER_ATTESTATION fixture verification, got %+v", optAuthzSum.FixtureVerification)
	}
	if optAuthzSum.BOPLA == nil || optAuthzSum.BOPLA.CleanupAttempted == 0 || optAuthzSum.BOPLA.CleanupRestored == 0 || optAuthzSum.BOPLA.CleanupFailed != 0 {
		t.Fatalf("expected verified reversible cleanup counts in authorization_summary.json, got %+v", optAuthzSum.BOPLA)
	}
	if sumBytes, err := json.Marshal(optAuthzSum); err == nil {
		t.Logf("OPTED_IN_FIXTURE_AUTHZ_SUMMARY=%s", string(sumBytes))
	}

	rep := readReportJSONFile(t, outDir)
	sawMassAssignVerified := false
	for _, f := range rep.Findings {
		if strings.Contains(f.Endpoint, "/api/profile") && strings.Contains(strings.ToUpper(f.Title), "MASS") {
			if strings.ToUpper(f.EvidenceDetails.Details["verification_state"]) == "VERIFIED" {
				sawMassAssignVerified = true
			}
		}
		if strings.Contains(f.Endpoint, "/api/preferences") && strings.ToUpper(f.EvidenceDetails.Details["verification_state"]) == "VERIFIED" {
			t.Fatalf("echoed-only /api/preferences must NOT reach VERIFIED, got %+v", f)
		}
	}
	if !sawMassAssignVerified {
		t.Fatalf("expected VERIFIED BOPLA mass assignment on /api/profile, findings=%+v", rep.Findings)
	}
}

func TestPhase4E2E_SingleIdentityAndDuplicateTokens_SafeDegradation(t *testing.T) {
	app := setupPhase4FixtureApp()
	defer app.server.Close()

	// Case 1: Single identity only (no User B, no Admin)
	outSingle := t.TempDir()
	out1, code1 := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "custom",
		"--modules", "recon,bola,bfla,bopla,authz",
		"--output", outSingle,
		"--auth-user-a", p4UserAToken,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code1 != 0 && code1 != 1 {
		t.Fatalf("single identity run failed with %d:\n%s", code1, out1)
	}
	sumSingle := readAuthzSummaryFile(t, outSingle)
	if sumSingle.BOLA == nil || sumSingle.BOLA.Status != "NOT_CONFIGURED" {
		t.Fatalf("expected BOLA NOT_CONFIGURED without User B, got %+v", sumSingle.BOLA)
	}
	if sumSingle.BOLA.VerifiedCount != 0 {
		t.Fatalf("expected 0 verified BOLA without second identity, got %d", sumSingle.BOLA.VerifiedCount)
	}

	// Case 2: Duplicate identical token passed for User A and User B
	outDup := t.TempDir()
	out2, code2 := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "custom",
		"--modules", "recon,bola,authz",
		"--output", outDup,
		"--auth-user-a", p4UserAToken,
		"--auth-user-b", p4UserAToken,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code2 != 0 && code2 != 1 {
		t.Fatalf("duplicate identity run failed with %d:\n%s", code2, out2)
	}
	sumDup := readAuthzSummaryFile(t, outDup)
	if sumDup.BOLA == nil || sumDup.BOLA.VerifiedCount != 0 {
		t.Fatalf("expected identical USER_A/USER_B credentials NOT to verify BOLA, got %+v", sumDup.BOLA)
	}
	assertNoSecretLeakInOutputs(t, outDup, out2, []string{p4UserAToken})
}

func TestPhase4E2E_CookieRolesConfig_IsolatedMultiIdentity(t *testing.T) {
	app := setupPhase4FixtureApp()
	defer app.server.Close()

	rolesPath := filepath.Join(t.TempDir(), "roles_cookies.json")
	rolesJSON := fmt.Sprintf(`{
  "user_a": {"cookie": "felix_sid=%s", "username": "alice", "role": "user"},
  "user_b": {"cookie": "felix_sid=%s", "username": "bob", "role": "user"},
  "admin":  {"cookie": "felix_sid=%s", "username": "admin", "role": "admin"}
}`, p4UserACookie, p4UserBCookie, p4AdminCookie)
	if err := os.WriteFile(rolesPath, []byte(rolesJSON), 0600); err != nil {
		t.Fatalf("write roles config: %v", err)
	}

	outDir := t.TempDir()
	out, code := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "api",
		"--roles-config", rolesPath,
		"--output", outDir,
		"--auth-confirm",
		"--allow-loopback",
		"--crawl-depth", "3",
		"--crawl-max-pages", "40",
		"--crawl-max-requests", "120",
	)
	if code != 0 && code != 1 {
		t.Fatalf("cookie roles-config run failed with %d:\n%s", code, out)
	}

	assertNoDestructiveHits(t, app)
	assertNoBleedErrors(t, app)
	assertNoSecretLeakInOutputs(t, outDir, out, []string{p4UserACookie, p4UserBCookie, p4AdminCookie, p4APISecret})

	app.mu.Lock()
	sawA := app.seenAuthUsers["USER_A"]
	sawB := app.seenAuthUsers["USER_B"]
	sawAdm := app.seenAuthUsers["ADMIN"]
	app.mu.Unlock()
	if !sawA || !sawB || !sawAdm {
		t.Fatalf("expected all three cookie identities executed against server: A=%v B=%v Admin=%v", sawA, sawB, sawAdm)
	}

	sum := readAuthzSummaryFile(t, outDir)
	if sum.BOLA == nil || sum.BOLA.VerifiedCount == 0 {
		t.Fatalf("expected cookie-session BOLA finding, got %+v", sum.BOLA)
	}
	if sum.BFLA == nil || sum.BFLA.VerifiedCount == 0 {
		t.Fatalf("expected cookie-session BFLA finding, got %+v", sum.BFLA)
	}
	if sum.BOPLA == nil || sum.BOPLA.VerifiedCount == 0 {
		t.Fatalf("expected cookie-session BOPLA finding, got %+v", sum.BOPLA)
	}
}

func TestPhase4E2E_BudgetCapEnforced(t *testing.T) {
	app := setupPhase4FixtureApp()
	defer app.server.Close()

	outDir := t.TempDir()
	out, code := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "custom",
		"--modules", "recon,bola,bfla,bopla,authz",
		"--output", outDir,
		"--auth-user-a", p4UserAToken,
		"--auth-user-b", p4UserBToken,
		"--auth-admin", p4AdminToken,
		"--authz-max-requests", "6",
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("budget cap run failed with %d:\n%s", code, out)
	}
	sum := readAuthzSummaryFile(t, outDir)
	if sum.RequestsSent > 8 { // allows bounded discovery JSON probes outside BOLA/BFLA/BOPLA or within slight tolerance
		t.Fatalf("expected --authz-max-requests 6 budget enforced closely, got requests_sent=%d", sum.RequestsSent)
	}
}

func TestPhase4E2E_SyntheticFixtureVerification_HardenedGates(t *testing.T) {
	t.Run("UnverifiedLoopbackWithoutHeaderOrExplicitHost_Blocked", func(t *testing.T) {
		app := setupPhase4FixtureAppWithOpts(phase4FixtureOpts{fixtureHeader: false})
		defer app.server.Close()

		outDir := t.TempDir()
		out, code := runFelix(t, "assess",
			"--target", app.server.URL,
			"--profile", "custom",
			"--modules", "recon,bopla,authz",
			"--output", outDir,
			"--auth-user-a", p4UserAToken,
			"--auth-user-b", p4UserBToken,
			"--auth-admin", p4AdminToken,
			"--allow-state-changing",
			"--synthetic-fixture",
			"--auth-confirm",
			"--allow-loopback",
		)
		if code != 0 && code != 1 {
			t.Fatalf("unexpected exit code %d:\n%s", code, out)
		}
		if hits := atomic.LoadInt32(&app.profileWriteHits); hits != 0 {
			t.Fatalf("expected 0 writes when loopback lacks header attestation and --fixture-hosts, got %d", hits)
		}
		sum := readAuthzSummaryFile(t, outDir)
		if sum.FixtureVerification == nil || sum.FixtureVerification.Verified || sum.FixtureVerification.Method != "FAILED_UNVERIFIED_TARGET" {
			t.Fatalf("expected FAILED_UNVERIFIED_TARGET, got %+v", sum.FixtureVerification)
		}
	})

	t.Run("ProductionMarker_BlocksEvenWithExplicitFixtureHosts", func(t *testing.T) {
		app := setupPhase4FixtureAppWithOpts(phase4FixtureOpts{fixtureHeader: true, prodMarkerHeader: true})
		defer app.server.Close()

		parsedURL, err := url.Parse(app.server.URL)
		if err != nil {
			t.Fatalf("parse URL: %v", err)
		}

		outDir := t.TempDir()
		out, code := runFelix(t, "assess",
			"--target", app.server.URL,
			"--profile", "custom",
			"--modules", "recon,bopla,authz",
			"--output", outDir,
			"--auth-user-a", p4UserAToken,
			"--auth-user-b", p4UserBToken,
			"--auth-admin", p4AdminToken,
			"--allow-state-changing",
			"--synthetic-fixture",
			"--fixture-hosts", parsedURL.Host,
			"--auth-confirm",
			"--allow-loopback",
		)
		if code != 0 && code != 1 {
			t.Fatalf("unexpected exit code %d:\n%s", code, out)
		}
		if hits := atomic.LoadInt32(&app.profileWriteHits); hits != 0 {
			t.Fatalf("expected 0 writes when target advertises X-Environment: production, got %d", hits)
		}
		sum := readAuthzSummaryFile(t, outDir)
		if sum.FixtureVerification == nil || sum.FixtureVerification.Verified || sum.FixtureVerification.Method != "FAILED_PRODUCTION_MARKER" {
			t.Fatalf("expected FAILED_PRODUCTION_MARKER, got %+v", sum.FixtureVerification)
		}
	})

	t.Run("ExplicitFixtureHosts_PermitsPinnedLoopbackWithoutHeader", func(t *testing.T) {
		app := setupPhase4FixtureAppWithOpts(phase4FixtureOpts{fixtureHeader: false})
		defer app.server.Close()

		parsedURL, err := url.Parse(app.server.URL)
		if err != nil {
			t.Fatalf("parse URL: %v", err)
		}

		outDir := t.TempDir()
		out, code := runFelix(t, "assess",
			"--target", app.server.URL,
			"--profile", "custom",
			"--modules", "recon,bopla,authz",
			"--output", outDir,
			"--auth-user-a", p4UserAToken,
			"--auth-user-b", p4UserBToken,
			"--auth-admin", p4AdminToken,
			"--allow-state-changing",
			"--synthetic-fixture",
			"--fixture-hosts", parsedURL.Host,
			"--auth-confirm",
			"--allow-loopback",
		)
		if code != 0 && code != 1 {
			t.Fatalf("unexpected exit code %d:\n%s", code, out)
		}
		if hits := atomic.LoadInt32(&app.profileWriteHits); hits == 0 {
			t.Fatalf("expected pinned --fixture-hosts run to execute BOPLA writes")
		}
		sum := readAuthzSummaryFile(t, outDir)
		if sum.FixtureVerification == nil || !sum.FixtureVerification.Verified || sum.FixtureVerification.Method != "EXPLICIT_FIXTURE_HOST" {
			t.Fatalf("expected EXPLICIT_FIXTURE_HOST, got %+v", sum.FixtureVerification)
		}
	})
}

func TestPhase4E2E_MassAssignment_CleanupFailureSurfacedEndToEnd(t *testing.T) {
	app := setupPhase4FixtureAppWithOpts(phase4FixtureOpts{
		fixtureHeader:      true,
		failProfileRestore: true,
	})
	defer app.server.Close()

	outDir := t.TempDir()
	out, code := runFelix(t, "assess",
		"--target", app.server.URL,
		"--profile", "custom",
		"--modules", "recon,bopla,authz",
		"--output", outDir,
		"--auth-user-a", p4UserAToken,
		"--auth-user-b", p4UserBToken,
		"--auth-admin", p4AdminToken,
		"--allow-state-changing",
		"--synthetic-fixture",
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("cleanup failure run should complete cleanly without crash, got exit %d:\n%s", code, out)
	}

	sum := readAuthzSummaryFile(t, outDir)
	if sum.BOPLA == nil || sum.BOPLA.CleanupFailed != 1 || sum.BOPLA.CleanupAttempted != 3 {
		t.Fatalf("expected BOPLA CleanupFailed=1 CleanupAttempted=3 (2 restored is_admin + 1 failed role restore before halt), got %+v", sum.BOPLA)
	}
	if sum.BOPLA.SkippedCount == 0 {
		t.Fatalf("expected subsequent BOPLA mutation probes to be skipped after cleanup failure, got %+v", sum.BOPLA)
	}
	if hits := atomic.LoadInt32(&app.profileWriteHits); hits != 6 {
		t.Fatalf("expected PUT /api/profile hits to stop at 6 (4 is_admin writes/restores + USER_A role mutation + 1 failed restore; USER_B halted), got %d", hits)
	}
	foundHaltSkipped := false
	for _, item := range sum.CoverageItems {
		if item.Engine == "BOPLA" && item.Outcome == "SKIPPED" && strings.Contains(item.Reason, "prior restoration failure") {
			foundHaltSkipped = true
			break
		}
	}
	if !foundHaltSkipped {
		t.Fatalf("expected BOPLA coverage item documenting skipped mutation due to prior restoration failure, got %+v", sum.CoverageItems)
	}
	if !strings.Contains(out, "BOPLA Cleanup:") {
		t.Fatalf("expected BOPLA Cleanup status line in stdout:\n%s", out)
	}

	rep := readReportJSONFile(t, outDir)
	foundCleanupFailed := false
	for _, f := range rep.Findings {
		if strings.Contains(f.Endpoint, "/api/profile") && f.EvidenceDetails.Details["cleanup_status"] == "CLEANUP_FAILED" {
			foundCleanupFailed = true
			if !strings.Contains(f.Evidence, "CLEANUP WARNING") {
				t.Fatalf("expected finding Evidence to preserve CLEANUP WARNING, got %s", f.Evidence)
			}
		}
	}
	if !foundCleanupFailed {
		t.Fatalf("expected at least one BOPLA finding carrying cleanup_status=CLEANUP_FAILED in assessment_report.json")
	}
}
