package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/auth"
)

func captureStdoutStderr(f func() int) (int, string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	outChan := make(chan string)
	errChan := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outChan <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errChan <- buf.String()
	}()

	code := f()

	_ = wOut.Close()
	_ = wErr.Close()

	os.Stdout = oldStdout
	os.Stderr = oldStderr

	outStr := <-outChan
	errStr := <-errChan

	_ = rOut.Close()
	_ = rErr.Close()

	return code, outStr, errStr
}

func TestCLI_AssessmentAuth_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentAuth([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment auth",
		"--run, --verify",
		"--dry-run",
		"--bearer",
		"--api-key",
		"--check-rate-limit",
		"--max-requests",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentHelp_IncludesAuthVerification(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessment([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out, "auth         Inspect authentication surfaces, or verify active authentication security (--run/--verify)") {
		t.Errorf("expected main assessment help to document active auth verification")
	}
	if !strings.Contains(out, "felix assessment auth <asm-ref> --run --bearer <token>") {
		t.Errorf("expected examples to include auth --run")
	}
}

func TestCLI_AssessmentAuth_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAuth([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentWithTarget(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-test",
		Name:      "CLI Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-auth-test",
		Ref:       "ASM-CLI-AUTH-01",
		ClientID:  client.ID,
		Name:      "CLI Auth Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-1",
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
			ID:                  "auth-cli-rec-1",
			AssessmentID:        asm.ID,
			AuthorizingParty:    "CISO Jane Doe",
			AuthorizationMethod: "WRITTEN_CONTRACT",
			Status:              assessment.AuthApproved,
			ValidFrom:           &past,
			ValidUntil:          &future,
			DateReceived:        past,
			CreatedAt:           time.Now().UTC(),
			UpdatedAt:           time.Now().UTC(),
		}
		_ = store.SetAuthorization(&authRec)
	}

	// Override default DB path for CLI tests by setting environment variable or monkey patching
	oldPath, hasOld := os.LookupEnv("FELIX_DB_PATH")
	os.Setenv("FELIX_DB_PATH", dbPath)

	cleanup := func() {
		store.Close()
		if hasOld {
			os.Setenv("FELIX_DB_PATH", oldPath)
		} else {
			os.Unsetenv("FELIX_DB_PATH")
		}
	}

	return &asm, cleanup
}

func TestCLI_AssessmentAuth_SecurityRefusal_Unauthorized(t *testing.T) {
	asm, cleanup := setupTestAssessmentWithTarget(t, "http://127.0.0.1:8080", false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAuth([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected security refusal exit code 1 when not authorized, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected security refusal message, got: %s", errOut)
	}
}

func TestCLI_AssessmentAuth_ActiveRun_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"profile":{"name":"Alice","role":"tester"}}`))
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentWithTarget(t, ts.URL, true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentAuth([]string{
			asm.Ref,
			"--run",
			"--bearer", "test_secret_bearer_token",
			"--allow-loopback",
			"--json",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for active run, got %d", code)
	}

	var rep auth.VerificationReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nOutput was: %s", err, out)
	}

	if rep.Summary.TotalPassed < 1 {
		t.Errorf("expected at least 1 passed check in JSON summary, got %d", rep.Summary.TotalPassed)
	}
	// Verify raw secret is NOT leaked in JSON output
	if strings.Contains(out, "test_secret_bearer_token") {
		t.Errorf("CRITICAL SECURITY LEAK: raw token leaked in CLI JSON output")
	}
}

func TestCLI_AssessmentAuth_DryRun(t *testing.T) {
	asm, cleanup := setupTestAssessmentWithTarget(t, "https://example.com", true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentAuth([]string{
			asm.Ref,
			"--dry-run",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run, got %d", code)
	}
	if !strings.Contains(out, "DRY-RUN PLAN") {
		t.Errorf("expected dry run header, got: %s", out)
	}
	if !strings.Contains(out, "SKIPPED") && !strings.Contains(out, "skipped") {
		t.Errorf("expected skipped checks in dry run plan output")
	}
}
