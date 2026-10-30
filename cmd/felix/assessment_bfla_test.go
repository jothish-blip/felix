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

func TestCLI_AssessmentBFLA_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment bfla",
		"--run",
		"--dry-run",
		"--target",
		"--endpoint",
		"--method",
		"--admin-token",
		"--user-token",
		"--admin-role",
		"--user-role",
		"--allow-state-changing",
		"--synthetic-fixture",
		"--max-requests",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentBFLA_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForBFLA(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_bfla_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-bfla-test",
		Name:      "CLI BFLA Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-bfla-test",
		Ref:       "ASM-CLI-BFLA-01",
		ClientID:  client.ID,
		Name:      "CLI BFLA Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-bfla-1",
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
			ID:                  "auth-cli-bfla-1",
			AssessmentID:        asm.ID,
			AuthorizingParty:    "Chief Security Officer",
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

func TestCLI_AssessmentBFLA_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBFLA(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run to exit 0, got %d, errOut: %s", code, errOut)
	}
	if !strings.Contains(out, "BFLA / BROKEN FUNCTION LEVEL AUTHORIZATION PLAN (DRY-RUN)") {
		t.Errorf("expected plan output header, got: %s", out)
	}
	if !strings.Contains(out, "TEST ID") || !strings.Contains(out, "ALLOWED ROLE") {
		t.Errorf("expected planned tests table columns, got: %s", out)
	}
}

func TestCLI_AssessmentBFLA_DryRun_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBFLA(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{asm.Ref, "--dry-run", "--json"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run JSON to exit 0, got %d, errOut: %s", code, errOut)
	}

	var plan map[string]interface{}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("failed to parse dry-run JSON output: %v\nOutput was:\n%s", err, out)
	}
	if plan["assessment_id"] != asm.ID {
		t.Errorf("expected assessment_id %s, got %v", asm.ID, plan["assessment_id"])
	}
	tests, ok := plan["tests"].([]interface{})
	if !ok || len(tests) == 0 {
		t.Errorf("expected non-empty tests array in dry-run JSON")
	}
}

func TestCLI_AssessmentBFLA_Unauthorized_Refused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// approveAuth = false
	asm, cleanup := setupTestAssessmentForBFLA(t, ts.URL, false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 when unapproved, got %d", code)
	}
	if !strings.Contains(errOut, "Refused") {
		t.Errorf("expected refusal message in stderr, got %q", errOut)
	}
}

func TestCLI_AssessmentBFLA_ActiveRun_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "admin") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","users":[{"id":1,"name":"admin"}],"metrics":42}`)
			return
		}
		// Denied for standard user
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBFLA(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{
			asm.Ref,
			"--run",
			"--allow-loopback",
			"--admin-token", "Bearer token_admin_123",
			"--user-token", "Bearer token_user_456",
		})
	})

	if code != 0 {
		t.Fatalf("expected run to exit 0, got %d, errOut: %s", code, errOut)
	}
	if !strings.Contains(out, "BFLA / BROKEN FUNCTION LEVEL AUTHORIZATION") {
		t.Errorf("expected BFLA header in output, got: %s", out)
	}
	if !strings.Contains(out, "Assessment Complete") {
		t.Errorf("expected Assessment Complete in output, got: %s", out)
	}
}

func TestCLI_AssessmentBFLA_ActiveRun_JSON_CleanOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "admin") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","users":[{"id":1,"name":"admin"}],"metrics":42}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBFLA(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBFLA([]string{
			asm.Ref,
			"--run",
			"--json",
			"--allow-loopback",
			"--admin-token", "Bearer token_admin_clean",
			"--user-token", "Bearer token_user_clean",
		})
	})

	if code != 0 {
		t.Fatalf("expected run to exit 0, got %d, errOut: %s", code, errOut)
	}

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("regression: BFLA JSON output has non-JSON prefix: %s", trimmed)
	}

	var jsonResult map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonResult); err != nil {
		t.Fatalf("regression: stdout failed to parse as JSON: %v\nOutput: %s", err, trimmed)
	}

	if jsonResult["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %q, got %v", asm.Ref, jsonResult["assessment_ref"])
	}
}
