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

func TestCLI_AssessmentWorkflow_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment workflow",
		"WORKFLOW-PREREQUISITE-SKIP",
		"WORKFLOW-INVALID-ORDER",
		"WORKFLOW-REPLAY-DUPLICATE",
		"WORKFLOW-TOKEN-REUSE",
		"WORKFLOW-IDENTITY-MISMATCH",
		"WORKFLOW-CONCURRENT-RACE",
		"--run",
		"--dry-run",
		"--target",
		"--policy",
		"--workflow",
		"--category",
		"--owner-token",
		"--attacker-token",
		"--allow-state-changing",
		"--synthetic-fixture",
		"--max-requests",
		"--concurrency",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentWorkflow_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForWorkflow(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_workflow_cli_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-wf-test",
		Name:      "CLI Workflow Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-wf-test",
		Ref:       "ASM-CLI-WF-01",
		ClientID:  client.ID,
		Name:      "CLI Workflow Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-wf-1",
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
			ID:                  "auth-cli-wf-1",
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

func TestCLI_AssessmentWorkflow_DryRun_SendsZeroRequests(t *testing.T) {
	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForWorkflow(t, ts.URL, false)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for dry-run, got %d", code)
	}
	if requestCount != 0 {
		t.Errorf("dry-run violated security invariant: dispatched %d network requests", requestCount)
	}
	if !strings.Contains(out, "WORKFLOW INTEGRITY ASSESSMENT PLAN (DRY-RUN)") {
		t.Errorf("expected dry-run plan header, got %s", out)
	}
	if !strings.Contains(out, "Planned Checks:") {
		t.Errorf("expected plan checks summary in output")
	}
}

func TestCLI_AssessmentWorkflow_DryRun_JSON(t *testing.T) {
	asm, cleanup := setupTestAssessmentForWorkflow(t, "http://127.0.0.1:8080", false)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{asm.Ref, "--dry-run", "--json"})
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
	checks, ok := plan["planned_checks"].([]any)
	if !ok || len(checks) == 0 {
		t.Errorf("expected planned_checks array in JSON output")
	}
}

func TestCLI_AssessmentWorkflow_ActiveRun_MissingAuthRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForWorkflow(t, "http://127.0.0.1:8080", false) // approveAuth = false
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 when authorization missing, got %d", code)
	}
	if !strings.Contains(errOut, "authorization record is required") {
		t.Errorf("expected authorization required message, got %q", errOut)
	}
}

func TestCLI_AssessmentWorkflow_ActiveRun_MockExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForWorkflow(t, ts.URL, true)
	defer cleanup()

	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{
			asm.Ref,
			"--run",
			"--allow-loopback",
			"--owner-token", "token_owner",
			"--attacker-token", "token_attacker",
		})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for active workflow run, got %d", code)
	}
	if !strings.Contains(out, "Workflow Assessment Complete") {
		t.Errorf("expected completion message in output, got %s", out)
	}
	if !strings.Contains(out, "Findings:") {
		t.Errorf("expected findings summary line in output")
	}
}

func TestCLI_AssessmentWorkflow_ViewPastResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForWorkflow(t, ts.URL, true)
	defer cleanup()

	// 1. Run assessment to generate results
	codeRun, _, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{
			asm.Ref,
			"--run",
			"--allow-loopback",
		})
	})
	if codeRun != 0 {
		t.Fatalf("expected run to succeed, got exit code %d", codeRun)
	}

	// 2. View past results without --run or --dry-run
	codeView, outView, _ := captureStdoutStderr(func() int {
		return runAssessmentWorkflow([]string{asm.Ref})
	})
	if codeView != 0 {
		t.Errorf("expected exit code 0 when viewing past results, got %d", codeView)
	}
	if !strings.Contains(outView, "WORKFLOW INTEGRITY ASSESSMENT RESULTS") {
		t.Errorf("expected results header in output, got: %s", outView)
	}
	if !strings.Contains(outView, "Summary: Total Checks:") {
		t.Errorf("expected summary line in output, got: %s", outView)
	}
}
