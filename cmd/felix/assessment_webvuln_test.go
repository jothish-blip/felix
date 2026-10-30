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

func TestCLI_AssessmentWebVuln_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentWebVuln([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment webvuln",
		"--run",
		"--dry-run",
		"--category",
		"--status",
		"--canary",
		"--synthetic-fixture",
		"--allow-loopback",
		"--allow-private",
		"--json",
		"--verbose",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentWebVuln_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentWebVuln([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForWebVuln(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_webvuln_cli_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-webvuln-test",
		Name:      "CLI WebVuln Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-webvuln-test",
		Ref:       "ASM-CLI-WV-01",
		ClientID:  client.ID,
		Name:      "CLI WebVuln Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-wv-1",
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
			ID:                  "auth-cli-wv-1",
			AssessmentID:        asm.ID,
			AuthorizingParty:    "Chief Information Security Officer",
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

	_ = store.Close()

	origDB := os.Getenv("FELIX_DB_PATH")
	origDir := os.Getenv("FELIX_DIR")
	os.Setenv("FELIX_DB_PATH", dbPath)
	os.Setenv("FELIX_DIR", tmpDir)

	cleanup := func() {
		if origDB != "" {
			os.Setenv("FELIX_DB_PATH", origDB)
		} else {
			os.Unsetenv("FELIX_DB_PATH")
		}
		if origDir != "" {
			os.Setenv("FELIX_DIR", origDir)
		} else {
			os.Unsetenv("FELIX_DIR")
		}
	}

	return &asm, cleanup
}

func TestCLI_AssessmentWebVuln_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("dry run must NOT send any HTTP requests to target, got %s", r.URL.Path)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForWebVuln(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentWebVuln([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run, got %d (err: %s)", code, errOut)
	}
	if !strings.Contains(out, "WEB VULNERABILITY ENGINE PLAN (DRY-RUN)") {
		t.Errorf("expected plan output in dry run, got: %s", out)
	}
	if !strings.Contains(out, "SAFETY & VERIFICATION BOUNDARIES") {
		t.Errorf("expected safety boundaries in plan, got: %s", out)
	}
}

func TestCLI_AssessmentWebVuln_ActiveRun_MissingAuthRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForWebVuln(t, "https://app.example.com", false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentWebVuln([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected security refusal for missing auth, got: %s", errOut)
	}
}

func TestCLI_AssessmentWebVuln_ActiveRun_JSON_CleanOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Welcome</h1></body></html>`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForWebVuln(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentWebVuln([]string{asm.Ref, "--run", "--json", "--allow-loopback"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for active run with --json, got %d (err: %s)", code, errOut)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("stdout contained non-JSON banner pollution: %v\nOutput was: %s", err, out)
	}

	if parsed["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %s, got %v", asm.Ref, parsed["assessment_ref"])
	}
}
