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

func TestCLI_AssessmentSession_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment sessionsec",
		"--run",
		"--dry-run",
		"--target",
		"--login-url",
		"--logout-url",
		"--protected-url",
		"--cookie",
		"--allow-state-changing",
		"--policy",
		"--max-requests",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentSession_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForSession(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_session_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-sess-test",
		Name:      "CLI Session Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-sess-test",
		Ref:       "ASM-CLI-SESS-01",
		ClientID:  client.ID,
		Name:      "CLI Session Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-sess-1",
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
			ID:                  "auth-cli-sess-1",
			AssessmentID:        asm.ID,
			AuthorizingParty:    "Security Lead",
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

func TestCLI_AssessmentSession_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForSession(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run to exit 0, got %d, errOut: %s", code, errOut)
	}
	if !strings.Contains(out, "SESSION & IDENTITY SECURITY ENGINE PLAN (DRY-RUN)") {
		t.Errorf("expected plan output header, got: %s", out)
	}
	if !strings.Contains(out, "PLANNED SESSION & IDENTITY TESTS") {
		t.Errorf("expected planned tests section, got: %s", out)
	}
}

func TestCLI_AssessmentSession_DryRun_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForSession(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{asm.Ref, "--dry-run", "--json"})
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
	if !ok || len(tests) != 11 {
		t.Errorf("expected 11 planned tests in JSON, got %v", planMap["tests"])
	}
}

func TestCLI_AssessmentSession_Unauthorized_FailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Unauthorized assessment (approveAuth = false)
	asm, cleanup := setupTestAssessmentForSession(t, ts.URL, false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Fatalf("expected exit code 1 when running active test without authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected authorization refusal message, got %q", errOut)
	}
}

func TestCLI_AssessmentSession_ActiveRun_Authorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "pre_auth_cli_test", Path: "/"})
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	// Authorized assessment (approveAuth = true)
	asm, cleanup := setupTestAssessmentForSession(t, ts.URL, true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentSessionSec([]string{asm.Ref, "--run", "--max-requests", "15"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for authorized active assessment, got %d", code)
	}
	if !strings.Contains(out, "EXECUTING SESSION & IDENTITY SECURITY AUDIT") {
		t.Errorf("expected execution banner, got: %s", out)
	}
	if !strings.Contains(out, "CATEGORY COVERAGE SUMMARY") {
		t.Errorf("expected category coverage summary table in output, got: %s", out)
	}
}
