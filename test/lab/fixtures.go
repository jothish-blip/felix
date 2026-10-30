package lab

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/oast"
	"felix/pkg/report"
)

// BOLAFixtureMode controls whether the fixture behaves as vulnerable or fixed.
type BOLAFixtureMode string

const (
	BOLAModeVulnerable BOLAFixtureMode = "VULNERABLE"
	BOLAModeFixed       BOLAFixtureMode = "FIXED"
)

// BOLAFixture represents a controlled local HTTP server for BOLA assessment testing.
type BOLAFixture struct {
	server       *httptest.Server
	URL          string
	Mode         BOLAFixtureMode
	mu           sync.RWMutex
	requestLog   []string
	UserAToken   string
	UserBToken   string
	UserAResID   string
	UserBResID   string
	UserBSecret  string
}

// NewBOLAFixture creates and starts a controlled loopback fixture for BOLA testing.
func NewBOLAFixture(mode BOLAFixtureMode) *BOLAFixture {
	fix := &BOLAFixture{
		Mode:        mode,
		UserAToken:  "token_user_a_alice",
		UserBToken:  "token_user_b_bob",
		UserAResID:  "usr-1001",
		UserBResID:  "usr-1002",
		UserBSecret: "Bob Confidential Vault 789",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s Auth:%s", r.Method, r.URL.Path, r.Header.Get("Authorization")))
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// Identify requesting caller
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		var isUserA, isUserB bool
		if strings.Contains(authHeader, fix.UserAToken) {
			isUserA = true
		} else if strings.Contains(authHeader, fix.UserBToken) {
			isUserB = true
		}

		path := r.URL.Path

		// BOLA User Endpoint: /api/users/{id}
		if strings.HasPrefix(path, "/api/users/") {
			requestedID := strings.TrimPrefix(path, "/api/users/")

			if requestedID == fix.UserBResID {
				// User B owns usr-1002
				if isUserB {
					// Legitimate same-user owner access: 200 OK
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"id":             fix.UserBResID,
						"username":       "bob",
						"secret_profile": fix.UserBSecret,
						"role":           "member",
						"timestamp":      "2026-10-25T12:00:00Z",
					})
					return
				}

				if isUserA {
					// Non-owner User A attempts access
					fix.mu.RLock()
					currMode := fix.Mode
					fix.mu.RUnlock()

					if currMode == BOLAModeVulnerable {
						// VULNERABLE: Discloses User B's object to User A!
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"id":             fix.UserBResID,
							"username":       "bob",
							"secret_profile": fix.UserBSecret,
							"role":           "member",
							"timestamp":      "2026-10-25T12:00:00Z",
						})
						return
					}

					// FIXED: Correctly denies unauthorized cross-principal access
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error":   "unauthorized_object_access",
						"message": "Access denied: Principal does not own this object",
					})
					return
				}

				// Unauthenticated request to protected object
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "authentication_required",
				})
				return
			}

			if requestedID == fix.UserAResID {
				// User A owns usr-1001
				if isUserA {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"id":             fix.UserAResID,
						"username":       "alice",
						"secret_profile": "Alice Private Diary",
						"role":           "member",
					})
					return
				}
				if isUserB {
					fix.mu.RLock()
					currMode := fix.Mode
					fix.mu.RUnlock()
					if currMode == BOLAModeVulnerable {
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"id":             fix.UserAResID,
							"username":       "alice",
							"secret_profile": "Alice Private Diary",
							"role":           "member",
						})
						return
					}
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": "unauthorized_object_access",
					})
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Unknown object
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "object_not_found",
			})
			return
		}

		// Root / health / base endpoints
		if path == "/" || path == "/api" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"version": "lab-mock-1.0",
			})
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically flips between vulnerable and fixed mode.
func (f *BOLAFixture) SetMode(m BOLAFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// RequestCount returns total requests received.
func (f *BOLAFixture) RequestCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.requestLog)
}

// Close shuts down the test fixture server.
func (f *BOLAFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// JuiceShopMockFixture emulates key OWASP Juice Shop REST endpoints for offline testing.
type JuiceShopMockFixture struct {
	server *httptest.Server
	URL    string
}

// NewJuiceShopMockFixture initializes a mock Juice Shop server on loopback.
func NewJuiceShopMockFixture() *JuiceShopMockFixture {
	mux := http.NewServeMux()

	// Authentication endpoint
	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"token": "juice_shop_jwt_token_user_1",
				"bid":   1,
				"umail": "admin@juice-sh.op",
			},
		})
	})

	// Basket BOLA endpoint (/rest/basket/{id})
	mux.HandleFunc("/rest/basket/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		basketID := strings.TrimPrefix(r.URL.Path, "/rest/basket/")
		// Emulate Juice Shop BOLA: any caller can view any basket ID
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"id":         basketID,
				"UserId":     basketID,
				"Products":   []string{"Apple Juice", "Orange Juice"},
				"coupon":     "DISCOUNT2026",
			},
		})
	})

	server := httptest.NewServer(mux)
	return &JuiceShopMockFixture{
		server: server,
		URL:    server.URL,
	}
}

// Close terminates the mock Juice Shop server.
func (j *JuiceShopMockFixture) Close() {
	if j.server != nil {
		j.server.Close()
	}
}

// CRAPIMockFixture emulates key OWASP crAPI endpoints for offline testing.
type CRAPIMockFixture struct {
	server *httptest.Server
	URL    string
}

// NewCRAPIMockFixture initializes a mock crAPI server on loopback.
func NewCRAPIMockFixture() *CRAPIMockFixture {
	mux := http.NewServeMux()

	// Login endpoint
	mux.HandleFunc("/identity/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"token": "crapi_bearer_token_user_alice",
		})
	})

	// Vehicle Location BOLA endpoint (/vehicle/api/v1/vehicle/{vin}/location)
	mux.HandleFunc("/vehicle/api/v1/vehicle/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		vin := "default"
		if len(parts) >= 5 {
			vin = parts[4]
		}
		// Emulate crAPI BOLA: returns vehicle location without checking ownership
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vin":       vin,
			"latitude":  37.7749,
			"longitude": -122.4194,
			"owner":     "bob_vehicle_owner",
		})
	})

	server := httptest.NewServer(mux)
	return &CRAPIMockFixture{
		server: server,
		URL:    server.URL,
	}
}

// Close terminates the mock crAPI server.
func (c *CRAPIMockFixture) Close() {
	if c.server != nil {
		c.server.Close()
	}
}

// BFLAFixtureMode controls whether the BFLA fixture behaves as vulnerable or fixed.
type BFLAFixtureMode string

const (
	BFLAModeVulnerable BFLAFixtureMode = "VULNERABLE"
	BFLAModeFixed       BFLAFixtureMode = "FIXED"
)

// BFLAFixture represents a controlled local HTTP server for BFLA assessment testing.
type BFLAFixture struct {
	server     *httptest.Server
	URL        string
	Mode       BFLAFixtureMode
	mu         sync.RWMutex
	requestLog []string
	AdminToken string
	UserToken  string
}

// NewBFLAFixture creates a new controlled loopback BFLA fixture.
func NewBFLAFixture(mode BFLAFixtureMode) *BFLAFixture {
	fix := &BFLAFixture{
		Mode:       mode,
		AdminToken: "token_admin_bfla_alice",
		UserToken:  "token_user_bfla_bob",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s Auth:%s", r.Method, r.URL.Path, r.Header.Get("Authorization")))
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))

		isAdmin := strings.Contains(authHeader, fix.AdminToken)
		isUser := strings.Contains(authHeader, fix.UserToken)

		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/api/admin/metrics"):
			// Admin-only function
			if !isAdmin && !isUser {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "unauthorized",
					"message": "Missing authentication token",
				})
				return
			}

			if isAdmin {
				// Legitimate admin baseline access
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "ok",
					"role":   "admin",
					"admin_metrics": map[string]interface{}{
						"cpu_percent":     15.4,
						"active_sessions": 42,
						"system_settings": map[string]interface{}{"maintenance_mode": false},
					},
				})
				return
			}

			// Standard user attempting admin endpoint
			fix.mu.RLock()
			mode := fix.Mode
			fix.mu.RUnlock()

			if mode == BFLAModeVulnerable {
				// VULNERABLE: allows lower-privilege user to execute admin function
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "ok",
					"role":   "admin",
					"admin_metrics": map[string]interface{}{
						"cpu_percent":     15.4,
						"active_sessions": 42,
						"system_settings": map[string]interface{}{"maintenance_mode": false},
					},
				})
				return
			}

			// FIXED: denies lower-privilege user with 403 Forbidden
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "forbidden",
				"message": "Access denied: Requires administrative role",
			})
			return

		case strings.HasPrefix(path, "/api/user/profile"):
			// Permitted standard-user operation
			if !isAdmin && !isUser {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":           "ok",
				"user_id":          "usr-standard-1",
				"username":         "bob",
				"role":             "user",
				"dashboard_access": true,
			})
			return

		case path == "/" || path == "/api":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "healthy"})
			return

		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically changes BFLA fixture mode.
func (f *BFLAFixture) SetMode(m BFLAFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the BFLA fixture server.
func (f *BFLAFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// BOPLAFixtureMode controls whether the BOPLA fixture behaves as vulnerable or fixed.
type BOPLAFixtureMode string

const (
	BOPLAModeVulnerable BOPLAFixtureMode = "VULNERABLE"
	BOPLAModeFixed       BOPLAFixtureMode = "FIXED"
)

// BOPLAFixture represents a controlled local HTTP server for BOPLA / Mass Assignment testing.
type BOPLAFixture struct {
	server         *httptest.Server
	URL            string
	Mode           BOPLAFixtureMode
	mu             sync.RWMutex
	requestLog     []string
	AdminToken     string
	UserToken      string
	// Mutable test state
	ProfileID      string
	Username       string
	Bio            string
	Role           string
	IsAdmin        bool
	AccountBalance float64
	Salary         int
}

// NewBOPLAFixture creates a new controlled loopback BOPLA fixture.
func NewBOPLAFixture(mode BOPLAFixtureMode) *BOPLAFixture {
	fix := &BOPLAFixture{
		Mode:           mode,
		AdminToken:     "token_admin_bopla_charlie",
		UserToken:      "token_user_bopla_dave",
		ProfileID:      "usr-dave-01",
		Username:       "dave",
		Bio:            "Initial developer bio",
		Role:           "user",
		IsAdmin:        false,
		AccountBalance: 100.0,
		Salary:         120000,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s Auth:%s", r.Method, r.URL.Path, r.Header.Get("Authorization")))
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))

		isAdmin := strings.Contains(authHeader, fix.AdminToken)
		isUser := strings.Contains(authHeader, fix.UserToken)

		path := r.URL.Path

		if strings.HasPrefix(path, "/api/users/profile") {
			if !isAdmin && !isUser {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
				return
			}

			switch r.Method {
			case http.MethodGet:
				fix.mu.RLock()
				defer fix.mu.RUnlock()

				resp := map[string]interface{}{
					"id":             fix.ProfileID,
					"username":       fix.Username,
					"bio":            fix.Bio,
					"role":           fix.Role,
					"isAdmin":        fix.IsAdmin,
					"accountBalance": fix.AccountBalance,
				}

				// Salary is an admin-only property
				if isAdmin {
					resp["salary"] = fix.Salary
				} else if fix.Mode == BOPLAModeVulnerable {
					// Vulnerable BOPLA Read: exposes salary to standard user
					resp["salary"] = fix.Salary
				}
				// In Fixed Mode for non-admin: salary is omitted!

				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
				return

			case http.MethodPut, http.MethodPatch:
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad_request"})
					return
				}

				fix.mu.Lock()
				defer fix.mu.Unlock()

				if fix.Mode == BOPLAModeVulnerable {
					// VULNERABLE: Binds all parameters directly to internal state (Mass Assignment)
					if bio, ok := body["bio"].(string); ok {
						fix.Bio = bio
					}
					if role, ok := body["role"].(string); ok {
						fix.Role = role
					}
					if isAdminVal, ok := body["isAdmin"].(bool); ok {
						fix.IsAdmin = isAdminVal
					}
					if bal, ok := body["accountBalance"].(float64); ok {
						fix.AccountBalance = bal
					}
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"status":         "updated",
						"id":             fix.ProfileID,
						"username":       fix.Username,
						"bio":            fix.Bio,
						"role":           fix.Role,
						"isAdmin":        fix.IsAdmin,
						"accountBalance": fix.AccountBalance,
					})
					return
				}

				// FIXED: Safely ignores unauthorized properties (role, isAdmin, accountBalance)
				// Updates only permitted attributes (bio)
				if bio, ok := body["bio"].(string); ok {
					fix.Bio = bio
				}
				// role, isAdmin, accountBalance are safely ignored
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":         "updated",
					"id":             fix.ProfileID,
					"username":       fix.Username,
					"bio":            fix.Bio,
					"role":           fix.Role,
					"isAdmin":        fix.IsAdmin,
					"accountBalance": fix.AccountBalance,
				})
				return

			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}

		if path == "/" || path == "/api" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "healthy"})
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// Reset restores default disposable state.
func (f *BOPLAFixture) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Bio = "Initial developer bio"
	f.Role = "user"
	f.IsAdmin = false
	f.AccountBalance = 100.0
	f.Salary = 120000
}

// SetMode dynamically changes BOPLA fixture mode.
func (f *BOPLAFixture) SetMode(m BOPLAFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the BOPLA fixture server.
func (f *BOPLAFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// WEBVULN FIXTURE (XSS, SQLI, SSRF)
// -----------------------------------------------------------------------------

// WebVulnFixtureMode controls whether WebVuln endpoints behave as vulnerable or fixed.
type WebVulnFixtureMode string

const (
	WebVulnModeVulnerable WebVulnFixtureMode = "VULNERABLE"
	WebVulnModeFixed      WebVulnFixtureMode = "FIXED"
)

// WebVulnFixture provides controlled loopback endpoints for web vulnerability auditing.
type WebVulnFixture struct {
	server     *httptest.Server
	URL        string
	Mode       WebVulnFixtureMode
	mu         sync.RWMutex
	requestLog []string
}

// NewWebVulnFixture creates a local mock server with endpoints for XSS, SQLi, and SSRF.
func NewWebVulnFixture(mode WebVulnFixtureMode) *WebVulnFixture {
	fix := &WebVulnFixture{
		Mode: mode,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery))
		mode := fix.Mode
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		path := r.URL.Path

		// 1. Reflected XSS endpoint: /search
		if path == "/search" {
			q := r.URL.Query().Get("q")
			if q == "" {
				q = r.URL.Query().Get("search")
			}
			if q == "" {
				q = r.URL.Query().Get("name")
			}
			if q == "" {
				q = r.URL.Query().Get("input")
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)

			if mode == WebVulnModeVulnerable {
				// Reflect unescaped into executable JavaScript code context
				fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>Search</title></head><body><h1>Results</h1><script>var searchResult = %s;</script></body></html>", q)
			} else {
				// Reflect safely HTML-encoded
				fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>Search</title></head><body><h1>Results</h1><p>You searched for: %s</p></body></html>", html.EscapeString(q))
			}
			return
		}

		// 2. SQL Injection endpoint: /items
		if path == "/items" {
			id := r.URL.Query().Get("id")
			if id == "" {
				id = r.URL.Query().Get("item")
			}

			w.Header().Set("Content-Type", "application/json")

			// Baseline request with safe numeric parameter
			if id == "101" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"item_id":101,"name":"Standard Security Widget","category":"hardware","price":49.99}`)
				return
			}

			// Syntax disruption probe (e.g. 101')
			if strings.Contains(id, "'") {
				if mode == WebVulnModeVulnerable {
					w.WriteHeader(http.StatusInternalServerError)
					// Distinct database error signature matching sqlErrorSignatures
					fmt.Fprint(w, `{"error":"SQLite3::SQLException: near \"'\": syntax error in query SELECT * FROM items WHERE id='101''"}`)
				} else {
					// Fixed: Parameterized query rejects or safely queries without syntax disruption error
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprint(w, `{"error":"Invalid item identifier format","code":400}`)
				}
				return
			}

			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Item not found"}`)
			return
		}

		// 3. SSRF parameter surface: /fetch
		if path == "/fetch" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","fetched":false}`)
			return
		}

		// Health & Root
		if path == "/" || path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"healthy","service":"webvuln-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically switches WebVuln fixture between vulnerable and fixed.
func (f *WebVulnFixture) SetMode(m WebVulnFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the WebVuln fixture server.
func (f *WebVulnFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// APISEC FIXTURE (CORS, RECONCILIATION / SHADOW APIS, GRAPHQL INTROSPECTION)
// -----------------------------------------------------------------------------

// APISecFixtureMode controls whether APISec endpoints behave as vulnerable or fixed.
type APISecFixtureMode string

const (
	APISecModeVulnerable APISecFixtureMode = "VULNERABLE"
	APISecModeFixed      APISecFixtureMode = "FIXED"
)

// APISecFixture provides controlled loopback endpoints for OWASP API Security auditing.
type APISecFixture struct {
	server     *httptest.Server
	URL        string
	Mode       APISecFixtureMode
	mu         sync.RWMutex
	requestLog []string
}

// NewAPISecFixture creates a local mock server with endpoints for CORS, shadow routes, error disclosure, and GraphQL.
func NewAPISecFixture(mode APISecFixtureMode) *APISecFixture {
	fix := &APISecFixture{
		Mode: mode,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		mode := fix.Mode
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		path := r.URL.Path

		// 1. OpenAPI Spec Endpoint: /openapi.json
		if path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Lab API Security Target", "version": "1.0.0"},
  "paths": {
    "/api/v1/users": {
      "get": {
        "summary": "List Users",
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`)
			return
		}

		// 2. Documented API endpoint: /api/v1/users (with CORS check)
		if path == "/api/v1/users" {
			w.Header().Set("Content-Type", "application/json")
			if mode == APISecModeVulnerable {
				// Credentialed wildcard CORS misconfiguration -> VERIFIED API8
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else {
				// Safe specific origin and nosniff header
				w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"id":1,"username":"alice","role":"user"},{"id":2,"username":"bob","role":"user"}]`)
			return
		}

		// 3. Undocumented Shadow Route: /api/v1/admin/internal_export (API9 Candidate)
		if path == "/api/v1/admin/internal_export" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","export_id":"exp-9901","records_count":42,"sensitive_data_included":true}`)
			return
		}

		// 4. Verbose Error Disclosure endpoint: /api/v1/debug
		if path == "/api/v1/debug" {
			w.Header().Set("Content-Type", "text/plain")
			if mode == APISecModeVulnerable {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Traceback (most recent call last):\n  File \"/app/handlers/debug.py\", line 42, in get\n    db.connect(secret_key)\nFatal error: unhandled database connection exception\n")
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"error":"An unexpected error occurred. Request ID: req-987"}`)
			}
			return
		}

		// 5. GraphQL Introspection Endpoint: /graphql
		if path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			if mode == APISecModeVulnerable {
				// Introspection enabled: return schema types including sensitive ones
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"data":{"__schema":{"types":[{"name":"User"},{"name":"AdminMutation"},{"name":"PaymentSecret"},{"name":"ApiKey"}]}}}`)
			} else {
				// Introspection disabled
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"errors":[{"message":"GraphQL schema introspection is disabled in production environments"}]}`)
			}
			return
		}

		// Root / Health
		if path == "/" || path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"healthy","service":"apisec-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically changes APISec fixture mode.
func (f *APISecFixture) SetMode(m APISecFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the APISec fixture server.
func (f *APISecFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// AUTH FIXTURE (AUTHENTICATION VERIFICATION, PROTECTED ROUTES, MISSING/INVALID CREDS)
// -----------------------------------------------------------------------------

// AuthFixtureMode controls whether Auth endpoints behave as vulnerable or fixed.
type AuthFixtureMode string

const (
	AuthModeVulnerable AuthFixtureMode = "VULNERABLE"
	AuthModeFixed      AuthFixtureMode = "FIXED"
)

// AuthFixture provides controlled loopback endpoints for authentication mechanism verification.
type AuthFixture struct {
	server     *httptest.Server
	URL        string
	Mode       AuthFixtureMode
	ValidToken string
	mu         sync.RWMutex
	requestLog []string
}

// NewAuthFixture creates an authentication verification fixture.
func NewAuthFixture(mode AuthFixtureMode) *AuthFixture {
	fix := &AuthFixture{
		Mode:       mode,
		ValidToken: "test_auth_valid_token_123",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		currentMode := fix.Mode
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		path := r.URL.Path

		// 1. Protected endpoint: /api/protected
		if path == "/api/protected" {
			authHdr := r.Header.Get("Authorization")
			if authHdr == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"Missing authorization header","status":401}`)
				return
			}
			if !strings.Contains(authHdr, fix.ValidToken) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"Invalid or expired authorization token","status":401}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"profile":{"user_id":42,"username":"alice","role":"user","account_tier":"premium"}}`)
			return
		}

		// 2. Unprotected endpoint: /api/unprotected (flawed or fixed)
		if path == "/api/unprotected" {
			authHdr := r.Header.Get("Authorization")
			if currentMode == AuthModeVulnerable {
				// Flawed: allows unauthenticated caller to access sensitive account data
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"profile":{"user_id":99,"username":"admin","role":"administrator","secret_data":"confidential_vault_keys"}}`)
				return
			}
			// Fixed: enforces authentication
			if authHdr == "" || !strings.Contains(authHdr, fix.ValidToken) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"Authentication required","status":401}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"profile":{"user_id":99,"username":"admin","role":"administrator"}}`)
			return
		}

		// 3. Public endpoint: /api/public
		if path == "/api/public" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","documentation":"public api reference"}`)
			return
		}

		// 4. Error disclosure endpoint: /api/debug-error
		if path == "/api/debug-error" {
			if currentMode == AuthModeVulnerable {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Traceback (most recent call last):\n  File \"/app/auth.py\", line 102, in verify\n    raise AuthException(\"internal auth failed\")")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Unauthorized"}`)
			return
		}

		// Root / Health
		if path == "/" || path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"healthy","service":"auth-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically switches Auth fixture mode.
func (f *AuthFixture) SetMode(m AuthFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the Auth fixture server.
func (f *AuthFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// SESSIONSEC FIXTURE (COOKIE SECURITY FLAGS, SESSION INVALIDATION & LOGOUT)
// -----------------------------------------------------------------------------

// SessionSecFixtureMode controls whether SessionSec endpoints behave as vulnerable or fixed.
type SessionSecFixtureMode string

const (
	SessionSecModeVulnerable SessionSecFixtureMode = "VULNERABLE"
	SessionSecModeFixed      SessionSecFixtureMode = "FIXED"
)

// SessionSecFixture provides controlled loopback endpoints for session security and cookie audits.
type SessionSecFixture struct {
	server         *httptest.Server
	URL            string
	Mode           SessionSecFixtureMode
	activeSessions map[string]bool
	mu             sync.RWMutex
	requestLog     []string
}

// NewSessionSecFixture creates a session security lab fixture.
func NewSessionSecFixture(mode SessionSecFixtureMode) *SessionSecFixture {
	fix := &SessionSecFixture{
		Mode:           mode,
		activeSessions: make(map[string]bool),
	}
	// Seed initial active test sessions
	fix.activeSessions["flx_logout_test_session"] = true
	fix.activeSessions["flx_active_session"] = true

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		currentMode := fix.Mode
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		path := r.URL.Path

		// 1. Cookie inspection endpoint: /set-cookie or /
		if path == "/set-cookie" || path == "/" {
			w.Header().Set("Content-Type", "application/json")
			if currentMode == SessionSecModeVulnerable {
				// Vulnerable: missing Secure, missing HttpOnly, missing SameSite with __Host- prefix violation
				w.Header().Set("Set-Cookie", "__Host-session=flx_sess_insecure_token_abc; Path=/")
			} else {
				// Fixed: declares Secure, HttpOnly, SameSite=Strict
				w.Header().Set("Set-Cookie", "__Host-session=flx_sess_secure_token_abc; Path=/; Secure; HttpOnly; SameSite=Strict")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","cookie_configured":true}`)
			return
		}

		// 2. Logout endpoint: /logout
		if path == "/logout" {
			w.Header().Set("Content-Type", "application/json")
			if currentMode == SessionSecModeVulnerable {
				// Vulnerable: clears cookie in browser, but does NOT terminate session in server store
				w.Header().Set("Set-Cookie", "session=; Path=/; Max-Age=0")
			} else {
				// Fixed: clears cookie AND terminates server session
				fix.mu.Lock()
				delete(fix.activeSessions, "flx_logout_test_session")
				fix.mu.Unlock()
				w.Header().Set("Set-Cookie", "session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"logged_out"}`)
			return
		}

		// 3. Protected endpoint: /profile (tested during logout replay)
		if path == "/profile" {
			sessionCookie, _ := r.Cookie("session")
			sessVal := ""
			if sessionCookie != nil {
				sessVal = sessionCookie.Value
			}

			w.Header().Set("Content-Type", "application/json")
			if currentMode == SessionSecModeVulnerable {
				// In vulnerable mode, flx_logout_test_session is still accepted post-logout
				if sessVal == "flx_logout_test_session" || sessVal == "flx_active_session" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"profile":{"user":"alice","status":"active_dashboard","account":"001"}}`)
					return
				}
			} else {
				// In fixed mode, check activeSessions map
				fix.mu.RLock()
				isActive := fix.activeSessions[sessVal]
				fix.mu.RUnlock()
				if isActive && sessVal != "" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"profile":{"user":"alice","status":"active_dashboard","account":"001"}}`)
					return
				}
			}

			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Session expired or invalidated","login_required":true}`)
			return
		}

		// 4. Token handling endpoint: /api/auth/token
		if path == "/api/auth/token" {
			authHdr := r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(authHdr, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0") {
				// Unsecured none algorithm JWT
				if currentMode == SessionSecModeVulnerable {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"status":"ok","admin":true,"message":"Welcome admin"}`)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"Unsigned algorithm 'none' rejected","status":401}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"token_ok"}`)
			return
		}

		// Health
		if path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"healthy","service":"sessionsec-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically switches SessionSec fixture mode.
func (f *SessionSecFixture) SetMode(m SessionSecFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
	if m == SessionSecModeVulnerable {
		f.activeSessions["flx_logout_test_session"] = true
	}
}

// Close terminates the SessionSec fixture server.
func (f *SessionSecFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// AUTHZ FIXTURE (AUTHORIZATION MATRIX, BFLA, BOLA, ROLE BOUNDARIES)
// -----------------------------------------------------------------------------

// AuthzFixtureMode controls whether Authz endpoints behave as vulnerable or fixed.
type AuthzFixtureMode string

const (
	AuthzModeVulnerable AuthzFixtureMode = "VULNERABLE"
	AuthzModeFixed      AuthzFixtureMode = "FIXED"
)

// AuthzFixture provides controlled loopback endpoints for role-matrix and authorization tests.
type AuthzFixture struct {
	server     *httptest.Server
	URL        string
	Mode       AuthzFixtureMode
	mu         sync.RWMutex
	requestLog []string
}

// NewAuthzFixture creates an authorization matrix lab fixture.
func NewAuthzFixture(mode AuthzFixtureMode) *AuthzFixture {
	fix := &AuthzFixture{
		Mode: mode,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		currentMode := fix.Mode
		fix.mu.Unlock()

		// Scope Guard: Enforce loopback only
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "Forbidden: Non-loopback request blocked by security guard", http.StatusForbidden)
			return
		}

		path := r.URL.Path
		authHdr := r.Header.Get("Authorization")

		// 1. User profile endpoint: /api/user/profile (baseline for user and admin)
		if path == "/api/user/profile" {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(authHdr, "user_tok") || strings.Contains(authHdr, "admin_tok") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"user":"alice","profile_tier":"standard","status":"active"}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Authentication required"}`)
			return
		}

		// 2. Administrative function endpoint: /api/admin/system (BFLA check)
		if path == "/api/admin/system" {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(authHdr, "admin_tok") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"system_state":"healthy","admin":true,"cluster_nodes":4}`)
				return
			}
			if strings.Contains(authHdr, "user_tok") {
				if currentMode == AuthzModeVulnerable {
					// Vulnerable: low-privilege user can call admin function!
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"system_state":"healthy","admin":true,"cluster_nodes":4}`)
					return
				}
				// Fixed: proper 403 Forbidden
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":"Forbidden: Administrator privilege required","status":403}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Authentication required"}`)
			return
		}

		// 3. Object-level resource endpoint: /api/orders/order_101 (BOLA check)
		if strings.HasPrefix(path, "/api/orders/") {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(authHdr, "user_a_tok") {
				// Owner access: allow
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"order_id":"order_101","owner":"user_a","total":199.99,"items":["Widget A"]}`)
				return
			}
			if strings.Contains(authHdr, "user_b_tok") {
				if currentMode == AuthzModeVulnerable {
					// Vulnerable: User B can read User A's order
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"order_id":"order_101","owner":"user_a","total":199.99,"items":["Widget A"]}`)
					return
				}
				// Fixed: denies cross-tenant/cross-user access
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":"Forbidden: You do not own this order","status":403}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Authentication required"}`)
			return
		}

		// Root / Health
		if path == "/" || path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"healthy","service":"authz-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

// SetMode dynamically switches Authz fixture mode.
func (f *AuthzFixture) SetMode(m AuthzFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

// Close terminates the Authz fixture server.
func (f *AuthzFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// CloudSec Fixture (P15.5)
// -----------------------------------------------------------------------------

// CloudSecFixtureMode controls whether the fixture simulates vulnerable public cloud assets or fixed/restricted ones.
type CloudSecFixtureMode string

const (
	CloudSecModeVulnerable CloudSecFixtureMode = "VULNERABLE"
	CloudSecModeFixed       CloudSecFixtureMode = "FIXED"
)

// CloudSecFixture simulates cloud storage endpoints (S3, Azure Blob, GCS) and metadata SSRF probes.
type CloudSecFixture struct {
	server        *httptest.Server
	URL           string
	Mode          CloudSecFixtureMode
	mu            sync.RWMutex
	requestLog    []string
	S3ProbeHits   int
	BlobProbeHits int
	MetadataHits  int
}

// NewCloudSecFixture starts a loopback server simulating cloud services and metadata protection.
func NewCloudSecFixture(mode CloudSecFixtureMode) *CloudSecFixture {
	fix := &CloudSecFixture{
		Mode:       mode,
		requestLog: make([]string, 0),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		currentMode := fix.Mode
		path := r.URL.Path
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s?%s", r.Method, path, r.URL.RawQuery))
		fix.mu.Unlock()

		// 1. AWS S3 Simulation (/s3-bucket/ or /storage/s3-bucket/)
		if strings.Contains(path, "s3") || strings.HasPrefix(path, "/storage/s3") {
			fix.mu.Lock()
			fix.S3ProbeHits++
			fix.mu.Unlock()

			w.Header().Set("Server", "AmazonS3")
			w.Header().Set("x-amz-request-id", "TX-AMZ-MOCK-12345")

			if currentMode == CloudSecModeVulnerable {
				// Vulnerable: public readable bucket listing
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>public-company-data</Name><MaxKeys>0</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
				return
			}

			// Fixed: private bucket returning 403 Forbidden
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
			return
		}

		// 2. Azure Blob Simulation (/blob/ or /storage/blob/)
		if strings.Contains(path, "blob") || strings.HasPrefix(path, "/storage/blob") {
			fix.mu.Lock()
			fix.BlobProbeHits++
			fix.mu.Unlock()

			w.Header().Set("Server", "Windows-Azure-Blob/1.0")
			w.Header().Set("x-ms-request-id", "ms-mock-uuid-67890")

			if currentMode == CloudSecModeVulnerable {
				if r.Method == http.MethodHead {
					w.Header().Set("x-ms-blob-public-access", "container")
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="public-media"><Blobs></Blobs></EnumerationResults>`)
				return
			}

			w.WriteHeader(http.StatusForbidden)
			return
		}

		// 3. Metadata Redirect Probe (/meta-redirect or /metadata)
		if strings.Contains(path, "metadata") || strings.Contains(path, "meta-redirect") {
			fix.mu.Lock()
			fix.MetadataHits++
			fix.mu.Unlock()

			// Emulate open redirector redirecting to AWS IMDS IPv4
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}

		// Root / Health / Neutral default
		if path == "/" || path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","service":"cloudsec-fixture"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

func (f *CloudSecFixture) SetMode(m CloudSecFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

func (f *CloudSecFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// OAST Fixture (P15.5)
// -----------------------------------------------------------------------------

// OASTFixture provides a fully controlled, local loopback OAST harness backed by pkg/oast.
type OASTFixture struct {
	Correlator *oast.Correlator
	Simulator  *oast.LocalSimulator
	URL        string
}

// NewOASTFixture instantiates an isolated in-process OAST correlator and local simulator listener.
func NewOASTFixture() (*OASTFixture, error) {
	cfg := oast.DefaultConfig()
	cfg.AllowLoopback = true
	cfg.DefaultTTL = 10 * time.Second

	correlator, err := oast.NewCorrelator(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAST correlator: %w", err)
	}

	simulator := oast.NewLocalSimulator(correlator)
	return &OASTFixture{
		Correlator: correlator,
		Simulator:  simulator,
		URL:        simulator.URL,
	}, nil
}

// Close terminates the simulator and closes the correlator.
func (f *OASTFixture) Close() {
	if f.Simulator != nil {
		f.Simulator.Close()
	}
}

// -----------------------------------------------------------------------------
// Workflow Fixture (P15.5)
// -----------------------------------------------------------------------------

// WorkflowFixtureMode controls whether the multi-step business workflow enforces state invariants or allows skips.
type WorkflowFixtureMode string

const (
	WorkflowModeVulnerable WorkflowFixtureMode = "VULNERABLE"
	WorkflowModeFixed       WorkflowFixtureMode = "FIXED"
)

// WorkflowFixture simulates multi-step business logic workflows (Draft -> Approval -> Fulfillment).
type WorkflowFixture struct {
	server       *httptest.Server
	URL          string
	Mode         WorkflowFixtureMode
	mu           sync.RWMutex
	requestLog   []string
	orderState   string
	callCounters map[string]int
}

// NewWorkflowFixture creates a new workflow test server.
func NewWorkflowFixture(mode WorkflowFixtureMode) *WorkflowFixture {
	fix := &WorkflowFixture{
		Mode:         mode,
		orderState:   "NONE",
		callCounters: make(map[string]int),
		requestLog:   make([]string, 0),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		currentMode := fix.Mode
		path := r.URL.Path
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, path))
		fix.callCounters[path]++
		fix.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		// Step 1: Draft Creation (/api/order/draft)
		if path == "/api/order/draft" {
			fix.mu.Lock()
			fix.orderState = "DRAFT"
			fix.mu.Unlock()

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"order_id":"ord-1001","status":"DRAFT","workflow_token":"wf-draft-token-abc"}`)
			return
		}

		// Step 2: Approval (/api/order/approve)
		if path == "/api/order/approve" {
			fix.mu.Lock()
			defer fix.mu.Unlock()

			if currentMode == WorkflowModeFixed {
				if r.Header.Get("X-Draft-Token") != "wf-draft-token-abc" {
					w.WriteHeader(http.StatusPreconditionFailed)
					fmt.Fprint(w, `{"error":"missing mandatory draft prerequisite token","status":"REJECTED"}`)
					return
				}
			}

			fix.orderState = "APPROVED"
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"order_id":"ord-1001","status":"APPROVED","workflow_token":"wf-approved-token-xyz"}`)
			return
		}

		// Step 3: Fulfillment (/api/order/fulfill)
		if path == "/api/order/fulfill" {
			fix.mu.Lock()
			defer fix.mu.Unlock()

			if currentMode == WorkflowModeVulnerable {
				// Vulnerable: Step 3 fulfills and completes the order even if Step 2 was omitted!
				fix.orderState = "COMPLETED"
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"order_id":"ord-1001","status":"COMPLETED","dispatched":true}`)
				return
			}

			// Fixed: strictly enforces predecessor state transition
			if r.Header.Get("X-Approval-Token") != "wf-approved-token-xyz" {
				w.WriteHeader(http.StatusPreconditionFailed)
				fmt.Fprint(w, `{"error":"mandatory prerequisite approval token missing","status":"REJECTED"}`)
				return
			}

			fix.orderState = "COMPLETED"
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"order_id":"ord-1001","status":"COMPLETED","dispatched":true}`)
			return
		}

		// Independent Read-Back Status Endpoint (/api/order/status)
		if path == "/api/order/status" {
			fix.mu.RLock()
			st := fix.orderState
			cnt := fix.callCounters["/api/order/fulfill"]
			fix.mu.RUnlock()

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"order_id":"ord-1001","status":"%s","fulfillment_count":%d}`, st, cnt)
			return
		}

		// Root / Health
		if path == "/" || path == "/health" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","service":"workflow-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

func (f *WorkflowFixture) SetMode(m WorkflowFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

func (f *WorkflowFixture) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orderState = "NONE"
	f.callCounters = make(map[string]int)
	f.requestLog = make([]string, 0)
}

func (f *WorkflowFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// -----------------------------------------------------------------------------
// P15.6 Secret Detection, Redaction & Evidence Integrity Lab Fixture
// -----------------------------------------------------------------------------

// SecretsFixtureMode controls the behavior and returned assets of SecretsFixture.
type SecretsFixtureMode string

const (
	SecretsModeCanaries    SecretsFixtureMode = "CANARIES"
	SecretsModeBenign      SecretsFixtureMode = "BENIGN"
	SecretsModeAmbiguous   SecretsFixtureMode = "AMBIGUOUS"
	SecretsModeAdversarial SecretsFixtureMode = "ADVERSARIAL"
)

// Synthetic canary constants used for positive detection and zero-leakage assertions.
const (
	LabCanaryAWSKey      = "AKIAIOSFODNN7EXAMPLE"
	LabCanaryGitHubToken = "ghp_123456789012345678901234567890123456"
	LabCanaryStripeKey   = "sk_live_51Abcdef1234567890abcdef1234567890"
	LabCanarySlackToken  = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	LabCanaryOpenAIKey   = "sk-proj-12345678901234567890123456789012345678901234567890"
	LabCanarySupabaseKey = "sb_secret_canaryservicekey1234567890"
	LabCanaryPEMKeyBody  = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6canarykey"
	LabCanaryEntropyStr  = "Kj89LmN20pQrStUvWxYz1234567890AbCdEf"
	LabCanaryXSSPayload  = "<script>alert('XSS_CANARY_P15_6')</script>"
)

// createLabJWT builds a valid synthetic JWT for lab testing.
func createLabJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("lab-synthetic-signature-1234567890"))
	return header + "." + payload + "." + sig
}

// SecretsFixture serves controlled loopback web assets for secret detection,
// redaction auditing, and evidence integrity validation.
type SecretsFixture struct {
	server     *httptest.Server
	URL        string
	Mode       SecretsFixtureMode
	mu         sync.RWMutex
	requestLog []string
}

// NewSecretsFixture starts a loopback server serving client scripts with secret canaries.
func NewSecretsFixture(mode SecretsFixtureMode) *SecretsFixture {
	fix := &SecretsFixture{
		Mode:       mode,
		requestLog: make([]string, 0),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.mu.Lock()
		currentMode := fix.Mode
		path := r.URL.Path
		fix.requestLog = append(fix.requestLog, fmt.Sprintf("%s %s", r.Method, path))
		fix.mu.Unlock()

		// 1. Root HTML structure referencing client bundle
		if path == "/" || path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Felix Secrets Lab Target</title>
    <script src="/static/app.js"></script>
</head>
<body>
    <h1>Felix Local Test Lab — Secrets & Integrity Target</h1>
</body>
</html>`)
			return
		}

		// 2. Client JavaScript Asset
		if path == "/static/app.js" {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.WriteHeader(http.StatusOK)

			switch currentMode {
			case SecretsModeCanaries:
				sbJWT := createLabJWT(map[string]interface{}{
					"iss":  "supabase",
					"role": "service_role",
				})
				jsContent := fmt.Sprintf(`
// Production client-side bundle with embedded synthetic canaries
const AWS_ACCESS_KEY = "%s";
const GITHUB_TOKEN = "%s";
const STRIPE_SECRET = "%s";
const SLACK_BOT_TOKEN = "%s";
const OPENAI_API_KEY = "%s";
const SUPABASE_SERVICE_KEY = "%s";
const SUPABASE_SERVICE_JWT = "%s";

/*
-----BEGIN PRIVATE KEY-----
%s
-----END PRIVATE KEY-----
*/
`, LabCanaryAWSKey, LabCanaryGitHubToken, LabCanaryStripeKey, LabCanarySlackToken,
					LabCanaryOpenAIKey, LabCanarySupabaseKey, sbJWT, LabCanaryPEMKeyBody)
				fmt.Fprint(w, jsContent)
				return

			case SecretsModeBenign:
				jsContent := `
// Client bundle containing only benign negative controls
const requestId = "e4eaaaf2-d142-11e1-b3e1-000000000000";
const buildCommitSha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const stripeTestKey = "sk_test_fakeTestKey1234567890abcdef";
const supabasePubKey = "sb_publishable_clientkey1234567890abcdef";
const dummyApiKey = "your_api_key";
const placeholderSecret = "replace_me";
const themeBg = "#f5f5f5";
const themeBorder = "rgba(255, 90, 95, 0.10)";
`
				fmt.Fprint(w, jsContent)
				return

			case SecretsModeAmbiguous:
				genJWT := createLabJWT(map[string]interface{}{
					"sub":  "user-100234",
					"name": "Jane Doe",
					"role": "member",
				})
				jsContent := fmt.Sprintf(`
// Ambiguous tokens and candidate high-entropy strings
const api_token = "%s";

// Padded separation to prevent heuristic spillover
const paddingBlockA = "padding_value_00000000000000000000000000000000000000000000000000000000000000000000000000000000";
const paddingBlockB = "padding_value_00000000000000000000000000000000000000000000000000000000000000000000000000000000";

// General unprivileged JWT surrounded by ordinary benign prose: keyword, keywords, author, keyboard
const clientProfile = "%s";
`, LabCanaryEntropyStr, genJWT)
				fmt.Fprint(w, jsContent)
				return

			case SecretsModeAdversarial:
				jsContent := fmt.Sprintf(`
// Adversarial inputs: HTML injection and malformed unclosed PEM blocks
const AWS_ACCESS_KEY = "%s"; // %s
const malformedPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0syntheticcanarytruncated";
`, LabCanaryAWSKey, LabCanaryXSSPayload)
				fmt.Fprint(w, jsContent)
				return
			}
		}

		// 3. API Config Endpoint returning connection strings
		if path == "/api/config" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","database_url":"postgres://synthetic_user:synthetic_super_secret_pw@127.0.0.1:5432/proddb"}`)
			return
		}

		// 4. Health / Root
		if path == "/health" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","service":"secrets-lab"}`)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	fix.server = server
	fix.URL = server.URL
	return fix
}

func (f *SecretsFixture) SetMode(m SecretsFixtureMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Mode = m
}

func (f *SecretsFixture) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestLog = make([]string, 0)
}

func (f *SecretsFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}


// =============================================================================
// COMPLIANCE ENGINE & REGULATORY LAB FIXTURES (P15.7)
// =============================================================================

type ComplianceFrameworkType string

const (
	FrameworkNIST_SP800_53  ComplianceFrameworkType = "nist-sp-800-53"
	FrameworkOWASP_API_2023 ComplianceFrameworkType = "owasp-api-2023"
	FrameworkSOC2_TSC        ComplianceFrameworkType = "soc2-tsc-2017"
)

// ComplianceFixture manages synthetic catalogs, mappings, gate policies,
// and remediation episodes for compliance engine testing.
type ComplianceFixture struct {
	mu sync.Mutex
}

// NewComplianceFixture creates a new compliance fixture manager.
func NewComplianceFixture() *ComplianceFixture {
	return &ComplianceFixture{}
}

func (f *ComplianceFixture) Close() {}

// CreateCatalog generates and writes a valid, full-featured control catalog JSON file.
func (f *ComplianceFixture) CreateCatalog(catType ComplianceFrameworkType, outDir string) (string, error) {
	var cat compliance.ControlCatalog

	switch catType {
	case FrameworkNIST_SP800_53:
		cat = compliance.ControlCatalog{
			SchemaVersion: "1.0",
			ID:            "nist-sp-800-53",
			Version:       "5.1.0",
			Title:         "NIST Special Publication 800-53 Revision 5",
			Framework:     "NIST-SP800-53",
			Description:   "Security and Privacy Controls for Information Systems and Organizations",
			Source: &compliance.CatalogSource{
				Name:            "NIST Computer Security Resource Center",
				Publisher:       "National Institute of Standards and Technology",
				IsAuthoritative: true,
			},
			Controls: []compliance.Control{
				{
					ID:          "AC-1",
					Title:       "Access Control Policy and Procedures",
					Description: "The organization develops, documents, and disseminates access control policies and procedures.",
					Severity:    "HIGH",
					Category:    "Access Control",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "AC-3",
					Title:       "Access Enforcement",
					Description: "The system enforces approved authorizations for logical access to information and system resources.",
					Severity:    "HIGH",
					Category:    "Access Control",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "IA-2",
					Title:       "Identification and Authentication (Organizational Users)",
					Description: "The system uniquely identifies and authenticates organizational users and processes acting on their behalf.",
					Severity:    "HIGH",
					Category:    "Identification and Authentication",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "SC-8",
					Title:       "Transmission Confidentiality and Integrity",
					Description: "The system protects the confidentiality and integrity of transmitted information.",
					Severity:    "MEDIUM",
					Category:    "System and Communications Protection",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "SC-28",
					Title:       "Protection of Information at Rest",
					Description: "The system protects the confidentiality and integrity of information at rest.",
					Severity:    "MEDIUM",
					Category:    "System and Communications Protection",
					Status:      compliance.StatusActive,
				},
			},
		}

	case FrameworkOWASP_API_2023:
		cat = compliance.ControlCatalog{
			SchemaVersion: "1.0",
			ID:            "owasp-api-2023",
			Version:       "1.0.0",
			Title:         "OWASP Top 10 API Security Risks 2023",
			Framework:     "OWASP-API",
			Description:   "Authoritative reference catalog for OWASP API Security Top 10 2023",
			Source: &compliance.CatalogSource{
				Name:            "OWASP Foundation",
				Publisher:       "OWASP API Security Project",
				IsAuthoritative: true,
			},
			Controls: []compliance.Control{
				{
					ID:          "API1:2023",
					Title:       "Broken Object Level Authorization",
					Description: "Object level authorization mechanisms must validate user permissions on every object request.",
					Severity:    "CRITICAL",
					Category:    "Authorization",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "API2:2023",
					Title:       "Broken Authentication",
					Description: "Authentication mechanisms must be securely implemented to protect identity and access tokens.",
					Severity:    "CRITICAL",
					Category:    "Authentication",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "API3:2023",
					Title:       "Broken Object Property Level Authorization",
					Description: "APIs must validate authorization to access and mutate specific object properties.",
					Severity:    "HIGH",
					Category:    "Data Exposure",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "API5:2023",
					Title:       "Broken Function Level Authorization",
					Description: "Access control policies must enforce authorization checks for administrative operations.",
					Severity:    "HIGH",
					Category:    "Authorization",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "API7:2023",
					Title:       "Server-Side Request Forgery",
					Description: "API endpoints fetching remote resources must validate destinations to prevent SSRF.",
					Severity:    "HIGH",
					Category:    "Input Validation",
					Status:      compliance.StatusActive,
				},
			},
		}

	case FrameworkSOC2_TSC:
		cat = compliance.ControlCatalog{
			SchemaVersion: "1.0",
			ID:            "soc2-tsc-2017",
			Version:       "1.0.0",
			Title:         "SOC 2 Trust Services Criteria 2017",
			Framework:     "SOC2",
			Description:   "Trust Services Criteria for Security, Availability, and Confidentiality",
			Source: &compliance.CatalogSource{
				Name:            "AICPA",
				Publisher:       "American Institute of CPAs",
				IsAuthoritative: true,
			},
			Controls: []compliance.Control{
				{
					ID:          "CC6.1",
					Title:       "Logical Access Controls",
					Description: "The entity implements logical access security software, infrastructure, and architectures.",
					Severity:    "HIGH",
					Category:    "Common Criteria",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "CC6.2",
					Title:       "User Registration and Access Modification",
					Description: "Prior to issuing credentials, the entity registers and authorizes new internal and external users.",
					Severity:    "HIGH",
					Category:    "Common Criteria",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "CC6.3",
					Title:       "Revocation of Access",
					Description: "The entity revokes logical access when employment or vendor contracts terminate.",
					Severity:    "MEDIUM",
					Category:    "Common Criteria",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "CC6.6",
					Title:       "Logical Boundaries and Boundary Protection",
					Description: "The entity implements boundary protection measures to safeguard system components.",
					Severity:    "HIGH",
					Category:    "Common Criteria",
					Status:      compliance.StatusActive,
				},
				{
					ID:          "CC6.7",
					Title:       "Transmission Data Protection",
					Description: "The entity restricts transmission of data to authorized parties and protects data in transit.",
					Severity:    "MEDIUM",
					Category:    "Common Criteria",
					Status:      compliance.StatusActive,
				},
			},
		}

	default:
		return "", fmt.Errorf("unsupported framework type %q", catType)
	}

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed marshaling catalog JSON: %w", err)
	}

	catPath := filepath.Join(outDir, string(catType)+"_catalog.json")
	if err := os.WriteFile(catPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed writing catalog file %s: %w", catPath, err)
	}

	return catPath, nil
}

// CreateMappingRuleSet generates and writes finding-to-control mapping rulesets.
func (f *ComplianceFixture) CreateMappingRuleSet(catType ComplianceFrameworkType, outDir string) (string, error) {
	var rs compliance.MappingRuleSet

	switch catType {
	case FrameworkNIST_SP800_53:
		rs = compliance.MappingRuleSet{
			SchemaVersion:        "1.0",
			ID:                   "map-nist-sp800-53",
			Version:              "1.0.0",
			Title:                "FELIX Findings to NIST SP 800-53 Mapping",
			TargetCatalogID:      "nist-sp-800-53",
			TargetCatalogVersion: "5.1.0",
			Rules: []compliance.MappingRule{
				{
					ID:              "RULE-NIST-BOLA-AC3",
					SourceRuleID:    "BOLA-USER-READ",
					TargetControlID: "AC-3",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Unauthorized cross-user object access directly breaches access enforcement requirements",
				},
				{
					ID:              "RULE-NIST-BOLA-AC1",
					SourceRuleID:    "BOLA-USER-READ",
					TargetControlID: "AC-1",
					Relationship:    compliance.RelationshipPartialEvidence,
					Confidence:      0.8,
					Rationale:       "BOLA occurrence provides partial evidence that access control policy is unenforced",
				},
				{
					ID:              "RULE-NIST-AUTH-IA2",
					SourceRuleID:    "AUTH-BYPASS",
					TargetControlID: "IA-2",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Authentication bypass directly violates user identification and authentication controls",
				},
				{
					ID:              "RULE-NIST-CRYPTO-SC8",
					SourceCategory:  "CRYPTO",
					TargetControlID: "SC-8",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      0.9,
					Rationale:       "Cryptographic flaw indicates failure in transmission confidentiality/integrity",
				},
			},
		}

	case FrameworkOWASP_API_2023:
		rs = compliance.MappingRuleSet{
			SchemaVersion:        "1.0",
			ID:                   "map-owasp-api-2023",
			Version:              "1.0.0",
			Title:                "FELIX Findings to OWASP API Security 2023 Mapping",
			TargetCatalogID:      "owasp-api-2023",
			TargetCatalogVersion: "1.0.0",
			Rules: []compliance.MappingRule{
				{
					ID:              "RULE-OWASP-API1",
					SourceRuleID:    "BOLA-USER-READ",
					TargetControlID: "API1:2023",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Direct BOLA flaw maps directly to OWASP API1:2023",
				},
				{
					ID:              "RULE-OWASP-API3",
					SourceRuleID:    "BOPLA-MASS-ASSIGNMENT",
					TargetControlID: "API3:2023",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Mass assignment and unauthorized property mutation map to OWASP API3:2023",
				},
				{
					ID:              "RULE-OWASP-API5",
					SourceRuleID:    "BFLA-ADMIN-CALL",
					TargetControlID: "API5:2023",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Administrative privilege escalation maps to OWASP API5:2023",
				},
			},
		}

	case FrameworkSOC2_TSC:
		rs = compliance.MappingRuleSet{
			SchemaVersion:        "1.0",
			ID:                   "map-soc2-tsc-2017",
			Version:              "1.0.0",
			Title:                "FELIX Findings to SOC 2 TSC 2017 Mapping",
			TargetCatalogID:      "soc2-tsc-2017",
			TargetCatalogVersion: "1.0.0",
			Rules: []compliance.MappingRule{
				{
					ID:              "RULE-SOC2-CC61",
					SourceRuleID:    "BOLA-USER-READ",
					TargetControlID: "CC6.1",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Logical access control failure maps directly to SOC 2 CC6.1",
				},
				{
					ID:              "RULE-SOC2-CC62",
					SourceRuleID:    "AUTH-BYPASS",
					TargetControlID: "CC6.2",
					Relationship:    compliance.RelationshipDirect,
					Confidence:      1.0,
					Rationale:       "Authentication bypass maps to SOC 2 user registration and authorization criteria CC6.2",
				},
			},
		}

	default:
		return "", fmt.Errorf("unsupported framework type %q", catType)
	}

	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed marshaling ruleset JSON: %w", err)
	}

	rsPath := filepath.Join(outDir, string(catType)+"_mapping.json")
	if err := os.WriteFile(rsPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed writing mapping ruleset file %s: %w", rsPath, err)
	}

	return rsPath, nil
}

// CreateMinimalValidCatalog generates the smallest conforming valid ControlCatalog.
func (f *ComplianceFixture) CreateMinimalValidCatalog(outDir string) (string, error) {
	cat := compliance.ControlCatalog{
		SchemaVersion: "1.0",
		ID:            "minimal-valid-cat",
		Version:       "1.0.0",
		Title:         "Minimal Valid Catalog",
		Controls: []compliance.Control{
			{
				ID:          "MIN-01",
				Title:       "Minimal Baseline Control",
				Description: "Basic security baseline check",
				Severity:    "LOW",
				Status:      compliance.StatusActive,
			},
		},
	}

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, "minimal_valid_catalog.json")
	return path, os.WriteFile(path, data, 0600)
}

// CreateInvalidCatalog generates various malformed, incomplete, or bounded oversized catalogs.
func (f *ComplianceFixture) CreateInvalidCatalog(kind string, outDir string) (string, error) {
	path := filepath.Join(outDir, "invalid_"+kind+".json")

	switch kind {
	case "missing_id":
		content := `{"schema_version":"1.0","version":"1.0.0","title":"Missing ID","controls":[{"id":"C-1","title":"C1","description":"D"}]}`
		return path, os.WriteFile(path, []byte(content), 0600)

	case "missing_controls":
		content := `{"schema_version":"1.0","id":"no-controls","version":"1.0.0","title":"No Controls","controls":[]}`
		return path, os.WriteFile(path, []byte(content), 0600)

	case "duplicate_ids":
		content := `{
  "schema_version": "1.0",
  "id": "dup-cat",
  "version": "1.0.0",
  "title": "Duplicate IDs Catalog",
  "controls": [
    {"id": "AC-1", "title": "Access Control 1", "description": "Desc 1"},
    {"id": "AC-1", "title": "Access Control 2", "description": "Desc 2"}
  ]
}`
		return path, os.WriteFile(path, []byte(content), 0600)

	case "malformed_json":
		content := `{"schema_version": "1.0", "id": "broken", "controls": [`
		return path, os.WriteFile(path, []byte(content), 0600)

	case "unsupported_version":
		content := `{"schema_version": "99.0", "id": "future-cat", "version": "1.0.0", "title": "Unsupported Version", "controls":[{"id":"C-1","title":"C1","description":"D"}]}`
		return path, os.WriteFile(path, []byte(content), 0600)

	case "empty":
		return path, os.WriteFile(path, []byte(""), 0600)

	case "oversized":
		// Payload exceeding MaxCatalogSizeBytes (10MB)
		fOut, err := os.Create(path)
		if err != nil {
			return "", err
		}
		defer fOut.Close()
		_, _ = fOut.WriteString(`{"schema_version":"1.0","id":"oversized","version":"1.0.0","title":"`)
		// Write 10.5 MB of padding
		buf := make([]byte, 1024*1024)
		for i := range buf {
			buf[i] = 'A'
		}
		for i := 0; i < 11; i++ {
			_, _ = fOut.Write(buf)
		}
		_, _ = fOut.WriteString(`","controls":[{"id":"C-1","title":"C1","description":"D"}]}`)
		return path, nil

	case "malicious_path":
		content := `{
  "schema_version": "1.0",
  "id": "malicious-cat",
  "version": "1.0.0",
  "title": "Path Traversal in Controls",
  "controls": [
    {"id": "../../../../etc/shadow", "title": "Malicious Control ID", "description": "<script>alert('XSS')</script>"}
  ]
}`
		return path, os.WriteFile(path, []byte(content), 0600)

	default:
		return "", fmt.Errorf("unknown invalid catalog kind %q", kind)
	}
}

// CreateFindingsJSON writes a list of findings to a JSON file.
func (f *ComplianceFixture) CreateFindingsJSON(findings []report.Finding, outDir, filename string) (string, error) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, filename)
	return path, os.WriteFile(path, data, 0600)
}

// CreatePositiveEvidenceJSON writes positive evidence records to a JSON file.
func (f *ComplianceFixture) CreatePositiveEvidenceJSON(evidence []compliance.PositiveEvidence, outDir, filename string) (string, error) {
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, filename)
	return path, os.WriteFile(path, data, 0600)
}

// CreateGatePolicy writes a ComplianceGatePolicy to a JSON file.
func (f *ComplianceFixture) CreateGatePolicy(policy *compliance.ComplianceGatePolicy, outDir, filename string) (string, error) {
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, filename)
	return path, os.WriteFile(path, data, 0600)
}

// SeedRemediationEpisodes seeds deterministic remediation records and history events for MTTR/SLA testing.
func (f *ComplianceFixture) SeedRemediationEpisodes(store *compliance.SQLiteComplianceStore, assessmentID string, baseTime time.Time, kp compliance.KeyProvider) error {
	// 1. Critical Finding: 24h SLA - Resolved in 12h (On-time)
	rec1 := &compliance.RemediationRecord{
		ID:                "rem:lab:crit-ontime",
		FindingID:         "F-BOLA-01",
		FindingTitle:      "Unauthorized Cross-User Object Read",
		FindingCategory:   "BOLA-USER-READ",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "AC-3",
		Severity:          "CRITICAL",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "CRITICAL:24h",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusRemediated,
		CompletedAt:       &[]time.Time{baseTime.Add(12 * time.Hour)}[0],
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime.Add(12 * time.Hour),
	}
	_ = store.SaveRemediationRecordWithKey(rec1, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec1.ID),
		RemediationID: rec1.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec1, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec1.ID),
		RemediationID: rec1.ID,
		EventType:     compliance.HistoryEventStatusChanged,
		FromStatus:    compliance.RemediationStatusOpen,
		ToStatus:      compliance.RemediationStatusRemediated,
		Timestamp:     baseTime.Add(12 * time.Hour),
	}, kp)

	// 2. Critical Finding: 24h SLA - Resolved in 36h (Late / Overdue)
	rec2 := &compliance.RemediationRecord{
		ID:                "rem:lab:crit-late",
		FindingID:         "F-BOLA-02",
		FindingTitle:      "Critical BOLA in Billing",
		FindingCategory:   "BOLA-USER-READ",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "AC-3",
		Severity:          "CRITICAL",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "CRITICAL:24h",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusRemediated,
		CompletedAt:       &[]time.Time{baseTime.Add(36 * time.Hour)}[0],
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime.Add(36 * time.Hour),
	}
	_ = store.SaveRemediationRecordWithKey(rec2, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec2.ID),
		RemediationID: rec2.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec2, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec2.ID),
		RemediationID: rec2.ID,
		EventType:     compliance.HistoryEventStatusChanged,
		FromStatus:    compliance.RemediationStatusOpen,
		ToStatus:      compliance.RemediationStatusRemediated,
		Timestamp:     baseTime.Add(36 * time.Hour),
	}, kp)

	// 3. High Finding: 7d SLA - Resolved in 72h (On-time)
	rec3 := &compliance.RemediationRecord{
		ID:                "rem:lab:high-ontime",
		FindingID:         "F-AUTH-01",
		FindingTitle:      "Broken Authentication Session Fixation",
		FindingCategory:   "AUTH-BYPASS",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "IA-2",
		Severity:          "HIGH",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "HIGH:7d",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(7 * 24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusRemediated,
		CompletedAt:       &[]time.Time{baseTime.Add(72 * time.Hour)}[0],
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime.Add(72 * time.Hour),
	}
	_ = store.SaveRemediationRecordWithKey(rec3, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec3.ID),
		RemediationID: rec3.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec3, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec3.ID),
		RemediationID: rec3.ID,
		EventType:     compliance.HistoryEventStatusChanged,
		FromStatus:    compliance.RemediationStatusOpen,
		ToStatus:      compliance.RemediationStatusRemediated,
		Timestamp:     baseTime.Add(72 * time.Hour),
	}, kp)

	// 4. Medium Finding: 30d SLA - Unresolved / Open
	rec4 := &compliance.RemediationRecord{
		ID:                "rem:lab:med-open",
		FindingID:         "F-CRYPTO-01",
		FindingTitle:      "Missing TLS HSTS Header",
		FindingCategory:   "CRYPTO",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "SC-8",
		Severity:          "MEDIUM",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "MEDIUM:30d",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(30 * 24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusOpen,
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(rec4, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec4.ID),
		RemediationID: rec4.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)

	// 5. Low Finding: Invalid timestamps (completion before start -> excluded)
	rec5 := &compliance.RemediationRecord{
		ID:                "rem:lab:low-invalid",
		FindingID:         "F-INFO-01",
		FindingTitle:      "Server Banner Disclosure",
		FindingCategory:   "INFO",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "SC-28",
		Severity:          "LOW",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "LOW:90d",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(90 * 24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusRemediated,
		CompletedAt:       &[]time.Time{baseTime.Add(-2 * time.Hour)}[0], // Completion precedes start!
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(rec5, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec5.ID),
		RemediationID: rec5.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec5, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec5.ID),
		RemediationID: rec5.ID,
		EventType:     compliance.HistoryEventStatusChanged,
		FromStatus:    compliance.RemediationStatusOpen,
		ToStatus:      compliance.RemediationStatusRemediated,
		Timestamp:     baseTime.Add(-2 * time.Hour),
	}, kp)

	// 6. Boundary Case: Exactly at 24h deadline (CompletedOnTime)
	rec6 := &compliance.RemediationRecord{
		ID:                "rem:lab:crit-boundary",
		FindingID:         "F-BOLA-03",
		FindingTitle:      "BOLA in Export Service",
		FindingCategory:   "BOLA-USER-READ",
		AssessmentID:      assessmentID,
		CatalogID:         "nist-sp-800-53:5.1.0",
		ControlID:         "AC-3",
		Severity:          "CRITICAL",
		SeveritySource:    "finding",
		PolicyID:          "policy-default",
		PolicyVersion:     "1.0.0",
		PolicyRuleMatched: "CRITICAL:24h",
		AssignedAt:        baseTime,
		SLAStartTime:      baseTime,
		Deadline:          baseTime.Add(24 * time.Hour),
		TimeBasis:         "ELAPSED_TIME",
		Status:            compliance.RemediationStatusRemediated,
		CompletedAt:       &[]time.Time{baseTime.Add(24 * time.Hour)}[0], // Exactly at deadline
		CreatedAt:         baseTime,
		UpdatedAt:         baseTime.Add(24 * time.Hour),
	}
	_ = store.SaveRemediationRecordWithKey(rec6, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec6.ID),
		RemediationID: rec6.ID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec6, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(rec6.ID),
		RemediationID: rec6.ID,
		EventType:     compliance.HistoryEventStatusChanged,
		FromStatus:    compliance.RemediationStatusOpen,
		ToStatus:      compliance.RemediationStatusRemediated,
		Timestamp:     baseTime.Add(24 * time.Hour),
	}, kp)

	return nil
}

// RealTargetInfo represents runtime parameters of a running real application benchmark.
type RealTargetInfo struct {
	BaseURL     string `json:"base_url"`
	Version     string `json:"version"`
	IsAvailable bool   `json:"is_available"`
}

// CheckRealJuiceShop probes whether an OWASP Juice Shop target is actively running on loopback.
func CheckRealJuiceShop(baseURL string) (*RealTargetInfo, error) {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:3000"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/rest/admin/application-version")
	if err != nil {
		return &RealTargetInfo{BaseURL: baseURL, IsAvailable: false}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &RealTargetInfo{BaseURL: baseURL, IsAvailable: false}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var data struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	return &RealTargetInfo{
		BaseURL:     baseURL,
		Version:     data.Version,
		IsAvailable: true,
	}, nil
}
