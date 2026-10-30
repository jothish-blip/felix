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

func TestCLI_AssessmentBOPLA_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment bopla",
		"--run",
		"--dry-run",
		"--target",
		"--endpoint",
		"--property",
		"--method",
		"--expected-access",
		"--mutation-value",
		"--read-back",
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

func TestCLI_AssessmentBOPLA_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForBOPLA(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_bopla_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-bopla-test",
		Name:      "CLI BOPLA Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-bopla-test",
		Ref:       "ASM-CLI-BOPLA-01",
		ClientID:  client.ID,
		Name:      "CLI BOPLA Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-bopla-1",
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
			ID:                  "auth-cli-bopla-1",
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

func TestCLI_AssessmentBOPLA_DryRun_SendsZeroRequests(t *testing.T) {
	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOPLA(t, ts.URL, false)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for dry-run, got %d", code)
	}
	if requestCount != 0 {
		t.Errorf("dry-run violated security invariant: dispatched %d network requests", requestCount)
	}
	if !strings.Contains(out, "BOPLA / BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION PLAN (DRY-RUN)") {
		t.Errorf("expected dry-run plan header, got %s", out)
	}
	if !strings.Contains(out, "Total Planned Tests:") {
		t.Errorf("expected plan test summary in output")
	}
}

func TestCLI_AssessmentBOPLA_DryRun_JSON(t *testing.T) {
	asm, cleanup := setupTestAssessmentForBOPLA(t, "http://127.0.0.1:8080", false)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{asm.Ref, "--dry-run", "--json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for dry-run json, got %d", code)
	}

	var plan map[string]any
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("expected valid JSON plan output, got parse error: %v (raw: %s)", err, out)
	}
	if plan["assessment_id"] != asm.ID {
		t.Errorf("expected assessment_id %s, got %v", asm.ID, plan["assessment_id"])
	}
	tests, ok := plan["tests"].([]any)
	if !ok || len(tests) == 0 {
		t.Errorf("expected planned tests array in JSON output")
	}
}

func TestCLI_AssessmentBOPLA_ActiveRun_MissingAuthRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForBOPLA(t, "http://127.0.0.1:8080", false) // approveAuth = false
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 when authorization missing, got %d", code)
	}
	if !strings.Contains(errOut, "Refused: Assessment lacks authorization record") {
		t.Errorf("expected authorization refused message, got %q", errOut)
	}
}

func TestCLI_AssessmentBOPLA_ActiveRun_MockExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")

		if r.URL.Path == "/api/users/profile" {
			if strings.Contains(authHdr, "token_admin") {
				// Admin sees salary
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"id":"usr-01","username":"alice","role":"admin","salary":150000}`)
				return
			}
			// User sees profile without salary
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"usr-01","username":"alice","role":"user"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOPLA(t, ts.URL, true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{
			asm.Ref,
			"--run",
			"--allow-loopback",
			"--admin-token", "token_admin",
			"--user-token", "token_user",
		})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for active BOPLA run, got %d", code)
	}
	if !strings.Contains(out, "BOPLA Assessment Complete") {
		t.Errorf("expected completion message in output, got %s", out)
	}
	if !strings.Contains(out, "Findings:") {
		t.Errorf("expected findings summary line in output")
	}
}

func TestCLI_AssessmentBOPLA_ActiveRun_JSON_CleanOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")

		if r.URL.Path == "/api/users/profile" {
			if strings.Contains(authHdr, "token_admin") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"id":"usr-01","username":"alice","role":"admin","salary":150000}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"usr-01","username":"alice","role":"user"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForBOPLA(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentBOPLA([]string{
			asm.Ref,
			"--run",
			"--json",
			"--allow-loopback",
			"--admin-token", "token_admin",
			"--user-token", "token_user",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, errOut: %s", code, errOut)
	}

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("regression: BOPLA JSON output has non-JSON prefix: %s", trimmed)
	}

	var jsonResult map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonResult); err != nil {
		t.Fatalf("regression: stdout failed to parse as JSON: %v\nOutput: %s", err, trimmed)
	}

	if jsonResult["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %q, got %v", asm.Ref, jsonResult["assessment_ref"])
	}
}
