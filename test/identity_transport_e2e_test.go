package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type endpointCallLog struct {
	Path           string
	Method         string
	Authorization  string
	Cookie         string
	DetectedCaller string
}

func setupControlledIdentityServer(t *testing.T) (*httptest.Server, *[]endpointCallLog, *sync.Mutex) {
	var logs []endpointCallLog
	var mu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		cookieHdr := r.Header.Get("Cookie")

		detected := "ANONYMOUS"
		if authHdr == "Bearer token_user_a" || strings.Contains(cookieHdr, "session_a") {
			detected = "USER_A"
		} else if authHdr == "Bearer token_user_b" || strings.Contains(cookieHdr, "session_b") {
			detected = "USER_B"
		} else if authHdr == "Bearer token_admin" || strings.Contains(cookieHdr, "session_admin") {
			detected = "ADMIN"
		} else if authHdr != "" {
			detected = "INVALID_AUTH"
		}

		mu.Lock()
		logs = append(logs, endpointCallLog{
			Path:           r.URL.Path,
			Method:         r.Method,
			Authorization:  authHdr,
			Cookie:         cookieHdr,
			DetectedCaller: detected,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Handle specific routes
		switch r.URL.Path {
		case "/":
			if detected == "INVALID_AUTH" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized_invalid_token"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Controlled Target Root</h1><a href="/public">Public</a><a href="/api/data">API</a></body></html>`))

		case "/public":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"public_data_available"}`))

		case "/user_a/private":
			if detected != "USER_A" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"requires_user_a_credential"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"owner":"user_a","secret":"user_a_confidential_vault"}`))

		case "/user_b/private":
			if detected != "USER_B" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"requires_user_b_credential"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"owner":"user_b","secret":"user_b_confidential_vault"}`))

		case "/admin/private":
			if detected != "ADMIN" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden_requires_admin"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"role":"admin","management_controls":"active"}`))

		case "/users/v1/name1":
			// BOLA endpoint simulation: User A owns this, but if User B accesses it, it reveals User A's email
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"name1","username":"name1","email":"mail1@mail.com"}`))

		case "/api", "/api/data":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_version":"1.0","services":["users","data"]}`))

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
	})

	server := httptest.NewServer(handler)
	return server, &logs, &mu
}

// 1. End-to-End: Unauthenticated Assessment must send zero credentials across all modules
func TestE2E_UnauthenticatedAssessment(t *testing.T) {
	ts, logs, mu := setupControlledIdentityServer(t)
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "quick",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("Expected assess exit code 0 or 1, got %d. Output:\n%s", code, out)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(*logs) == 0 {
		t.Fatalf("Expected requests to be made to controlled test server, got 0")
	}

	for _, entry := range *logs {
		if entry.Authorization != "" {
			t.Errorf("Unauthenticated assessment leaked Authorization header on %s %s: %q", entry.Method, entry.Path, entry.Authorization)
		}
		if entry.Cookie != "" {
			t.Errorf("Unauthenticated assessment leaked Cookie header on %s %s: %q", entry.Method, entry.Path, entry.Cookie)
		}
		if entry.DetectedCaller != "ANONYMOUS" {
			t.Errorf("Expected caller to be ANONYMOUS, got %s on %s", entry.DetectedCaller, entry.Path)
		}
	}
}

// 2. End-to-End: Authenticated User A Assessment propagates User A token to downstream modules
func TestE2E_AuthenticatedUserA_Assessment(t *testing.T) {
	ts, logs, mu := setupControlledIdentityServer(t)
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "standard",
		"--auth", "token_user_a",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("Expected assess exit code 0 or 1, got %d. Output:\n%s", code, out)
	}

	// Verify verification success banner in output
	if !strings.Contains(out, "Identity User A verified successfully") {
		t.Errorf("Expected output to report Identity User A verified successfully, got:\n%s", out)
	}

	mu.Lock()
	defer mu.Unlock()

	userACalls := 0
	for _, entry := range *logs {
		// CORS anonymous checks may execute as ANONYMOUS, but all active web/api probes should be USER_A
		if entry.DetectedCaller == "USER_A" {
			userACalls++
			if entry.Authorization != "Bearer token_user_a" {
				t.Errorf("Expected Bearer token_user_a for User A call, got: %q", entry.Authorization)
			}
		}
		if entry.DetectedCaller == "USER_B" || entry.DetectedCaller == "ADMIN" {
			t.Errorf("Unexpected identity %s observed during single User A assessment on %s", entry.DetectedCaller, entry.Path)
		}
	}

	if userACalls == 0 {
		t.Fatalf("Expected at least one request with User A credentials, got 0 out of %d total requests", len(*logs))
	}

	// Check that credentials NEVER appear in output deliverables
	jsonReportPath := filepath.Join(tmpOut, "assessment_report.json")
	reportBytes, err := os.ReadFile(jsonReportPath)
	if err != nil {
		t.Fatalf("Failed to read assessment_report.json: %v", err)
	}
	reportStr := string(reportBytes)

	if strings.Contains(reportStr, "token_user_a") {
		t.Errorf("CRITICAL SECURITY DEFECT: Raw credential 'token_user_a' leaked in assessment_report.json")
	}
}

// 3. End-to-End: Multi-Role Assessment isolates User A, User B, and Admin contexts
func TestE2E_MultiRole_BOLA_Assessment(t *testing.T) {
	ts, logs, mu := setupControlledIdentityServer(t)
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "full",
		"--auth-user-a", "token_user_a",
		"--auth-user-b", "token_user_b",
		"--auth-admin", "token_admin",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("Expected assess exit code 0 or 1, got %d. Output:\n%s", code, out)
	}

	mu.Lock()
	defer mu.Unlock()

	var countUserA, countUserB, countAdmin, countAnon int
	for _, entry := range *logs {
		switch entry.DetectedCaller {
		case "USER_A":
			countUserA++
			if entry.Authorization != "Bearer token_user_a" {
				t.Errorf("User A request carried wrong token: %q", entry.Authorization)
			}
		case "USER_B":
			countUserB++
			if entry.Authorization != "Bearer token_user_b" {
				t.Errorf("User B request carried wrong token: %q", entry.Authorization)
			}
		case "ADMIN":
			countAdmin++
			if entry.Authorization != "Bearer token_admin" {
				t.Errorf("Admin request carried wrong token: %q", entry.Authorization)
			}
		case "ANONYMOUS":
			countAnon++
			if entry.Authorization != "" {
				t.Errorf("Anonymous request carried non-empty Authorization: %q", entry.Authorization)
			}
		}
	}

	t.Logf("Multi-role dispatch counts: User A=%d, User B=%d, Admin=%d, Anon=%d (Total=%d)",
		countUserA, countUserB, countAdmin, countAnon, len(*logs))

	if countUserA == 0 {
		t.Errorf("Expected requests with User A identity, got 0")
	}
	if countUserB == 0 {
		t.Errorf("Expected BOLA requests with User B identity, got 0")
	}

	// Verify report exists and no tokens leaked
	jsonReportPath := filepath.Join(tmpOut, "assessment_report.json")
	reportBytes, err := os.ReadFile(jsonReportPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}
	reportStr := string(reportBytes)

	for _, secretToken := range []string{"token_user_a", "token_user_b", "token_admin"} {
		if strings.Contains(reportStr, secretToken) {
			t.Errorf("CRITICAL SECURITY DEFECT: Raw token %q leaked in report", secretToken)
		}
	}
}

// 4. End-to-End: Rejected credentials trigger session failure handling without false positives
func TestE2E_RejectedCredential_SessionFailureHandling(t *testing.T) {
	ts, _, _ := setupControlledIdentityServer(t)
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "standard",
		"--auth", "invalid_bad_token_401",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	// When credentials are rejected, assessment should reflect the failure
	t.Logf("Assess output:\n%s (Exit code: %d)", out, code)

	// Verify the warning banner appeared
	if !strings.Contains(out, "WARNING: Identity User A credential rejected by target") {
		t.Errorf("Expected warning about rejected credential in output, got:\n%s", out)
	}

	// Verify coverage matrix records inconclusive outcome
	covPath := filepath.Join(tmpOut, "coverage_matrix.json")
	covBytes, err := os.ReadFile(covPath)
	if err == nil {
		var covMap map[string]any
		if err := json.Unmarshal(covBytes, &covMap); err == nil {
			testsList, ok := covMap["tests"].([]any)
			if ok {
				foundInconclusive := false
				for _, ti := range testsList {
					if tMap, ok := ti.(map[string]any); ok {
						if tMap["outcome"] == "INCONCLUSIVE" && strings.Contains(fmt.Sprint(tMap["reason"]), "rejected") {
							foundInconclusive = true
							break
						}
					}
				}
				if !foundInconclusive {
					t.Errorf("Expected coverage matrix to record INCONCLUSIVE test due to rejected credentials")
				}
			}
		}
	}
}
