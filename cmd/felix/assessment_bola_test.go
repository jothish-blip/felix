package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
)

func TestCLI_AssessmentBOLA_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment bola",
		"--run",
		"--dry-run",
		"--target",
		"--endpoint",
		"--object-id",
		"--param",
		"--user-a-token",
		"--user-b-token",
		"--allow-state-changing",
		"--max-requests",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentBOLA_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForBOLA(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_bola_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-bola-test",
		Name:      "CLI BOLA Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-bola-test",
		Ref:       "ASM-CLI-BOLA-01",
		ClientID:  client.ID,
		Name:      "CLI BOLA Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-bola-1",
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.AddTarget(&target)

	if approveAuth {
		past := time.Now().UTC().Add(-1 * time.Hour)
		future := time.Now().UTC().Add(24 * time.Hour)
		authRec := assessment.AuthorizationRecord{
			ID:                  "auth-cli-bola-1",
			AssessmentID:        asm.ID,
			AuthorizingParty:    "Security Officer",
			AuthorizationMethod: "Written",
			Status:              assessment.AuthApproved,
			ValidFrom:           &past,
			ValidUntil:          &future,
			DateReceived:        past,
			CreatedAt:           time.Now().UTC(),
			UpdatedAt:           time.Now().UTC(),
		}
		_ = store.SetAuthorization(&authRec)
	}

	oldPath, hasOld := os.LookupEnv("FELIX_DB_PATH")
	os.Setenv("FELIX_DB_PATH", dbPath)

	cleanup := func() {
		store.Close()
		if hasOld {
			os.Setenv("FELIX_DB_PATH", oldPath)
		} else {
			os.Unsetenv("FELIX_DB_PATH")
		}
		os.RemoveAll(tmpDir)
	}

	return &asm, cleanup
}

func TestCLI_AssessmentBOLA_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run to exit 0, got %d, errOut: %s", code, errOut)
	}
	if !strings.Contains(out, "BOLA / BROKEN OBJECT LEVEL AUTHORIZATION PLAN (DRY-RUN)") {
		t.Errorf("expected plan output header, got: %s", out)
	}
	if !strings.Contains(out, "PLANNED BOLA TESTS") {
		t.Errorf("expected planned tests section, got: %s", out)
	}
}

func TestCLI_AssessmentBOLA_DryRun_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{asm.Ref, "--dry-run", "--json"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run --json to exit 0, got %d, errOut: %s", code, errOut)
	}

	var planMap map[string]interface{}
	if err := json.Unmarshal([]byte(out), &planMap); err != nil {
		t.Fatalf("expected valid JSON output from dry-run --json, got error: %v, raw: %s", err, out)
	}

	if planMap["assessment_id"] != asm.ID {
		t.Errorf("expected assessment_id %q, got %v", asm.ID, planMap["assessment_id"])
	}
	if planMap["target_url"] != strings.TrimRight(ts.URL, "/") {
		t.Errorf("expected target_url %q, got %v", ts.URL, planMap["target_url"])
	}
	tests, ok := planMap["tests"].([]interface{})
	if !ok || len(tests) == 0 {
		t.Errorf("expected planned tests in JSON, got %v", planMap["tests"])
	}
}

func TestCLI_AssessmentBOLA_Unauthorized_FailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Unauthorized assessment (approveAuth = false)
	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Fatalf("expected exit code 1 when running active test without authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected authorization refusal message, got %q", errOut)
	}
}

func TestCLI_AssessmentBOLA_ActiveRun_Authorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate object access: non-owner receives 403 Forbidden
		if strings.Contains(r.Header.Get("Authorization"), "synthetic_token_user_a") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		// Owner receives object
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-1002","name":"User 1002 Data"}`)
	}))
	defer ts.Close()

	// Authorized assessment (approveAuth = true)
	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{asm.Ref, "--run", "--endpoint", "/api/users/{id}", "--object-id", "usr-1002", "--max-requests", "15"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for authorized active assessment, got %d", code)
	}
	if !strings.Contains(out, "EXECUTING BOLA / IDOR VERIFICATION") {
		t.Errorf("expected execution banner, got: %s", out)
	}
	if !strings.Contains(out, "CATEGORY COVERAGE SUMMARY") {
		t.Errorf("expected category coverage summary table in output, got: %s", out)
	}
}

func TestCLI_AssessmentBOLA_DistinctUserTokensWired(t *testing.T) {
	var ownerReceivedToken, nonOwnerReceivedToken string
	var ownerReceivedCookie, nonOwnerReceivedCookie string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHeader := r.Header.Get("Authorization")
		cookie, _ := r.Cookie("user_sess")

		if strings.Contains(authHeader, "owner_b_token_live") {
			ownerReceivedToken = authHeader
			if cookie != nil {
				ownerReceivedCookie = cookie.Value
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"usr-secure-77","owner":"user_b","secret_vault":"gold"}`)
			return
		}
		if strings.Contains(authHeader, "accessor_a_token_live") {
			nonOwnerReceivedToken = authHeader
			if cookie != nil {
				nonOwnerReceivedCookie = cookie.Value
			}
			// Simulate authorization denial
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"unauthorized_object_access"}`)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{
			asm.Ref,
			"--run",
			"--endpoint", "/api/users/{id}",
			"--object-id", "usr-secure-77",
			"--user-a-token", "accessor_a_token_live",
			"--user-b-token", "owner_b_token_live",
			"--user-a-cookie", "user_sess=accessor_a_cookie_val",
			"--user-b-cookie", "user_sess=owner_b_cookie_val",
			"--max-requests", "15",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, errOut: %s", code, errOut)
	}

	// Prove owner baseline received User B's token and cookie
	if ownerReceivedToken != "Bearer owner_b_token_live" {
		t.Errorf("expected owner baseline request to receive 'Bearer owner_b_token_live', got %q", ownerReceivedToken)
	}
	if ownerReceivedCookie != "owner_b_cookie_val" {
		t.Errorf("expected owner baseline cookie to be 'owner_b_cookie_val', got %q", ownerReceivedCookie)
	}

	// Prove non-owner cross request received User A's token and cookie
	if nonOwnerReceivedToken != "Bearer accessor_a_token_live" {
		t.Errorf("expected non-owner cross request to receive 'Bearer accessor_a_token_live', got %q", nonOwnerReceivedToken)
	}
	if nonOwnerReceivedCookie != "accessor_a_cookie_val" {
		t.Errorf("expected non-owner cookie to be 'accessor_a_cookie_val', got %q", nonOwnerReceivedCookie)
	}

	// Prove tokens were NEVER mixed
	if strings.Contains(ownerReceivedToken, "accessor_a") || strings.Contains(nonOwnerReceivedToken, "owner_b") {
		t.Errorf("security violation: identity tokens mixed between principals")
	}

	// Prove tokens are NOT leaked into CLI output
	if strings.Contains(out, "accessor_a_token_live") || strings.Contains(out, "owner_b_token_live") {
		t.Errorf("security violation: live tokens exposed in CLI output")
	}
}

func TestCLI_AssessmentBOLA_ActiveRun_JSON_CleanOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Authorization"), "user_b") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"usr-clean-1","owner":"user_b","data":"protected_data"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOLA(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOLA([]string{
			asm.Ref,
			"--run",
			"--json",
			"--endpoint", "/api/users/{id}",
			"--object-id", "usr-clean-1",
			"--user-a-token", "clean_token_a",
			"--user-b-token", "clean_token_b",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, errOut: %s", code, errOut)
	}

	// Regression test: Verify stdout contains purely valid JSON without banner text prefixes
	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("regression: stdout has non-JSON prefix: %s", trimmed[:min(len(trimmed), 100)])
	}

	var jsonResult map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonResult); err != nil {
		t.Fatalf("regression: stdout failed to parse as JSON: %v\nOutput: %s", err, trimmed)
	}

	if jsonResult["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %q, got %v", asm.Ref, jsonResult["assessment_ref"])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
