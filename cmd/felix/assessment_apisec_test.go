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

func TestCLI_AssessmentAPISec_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment apisec",
		"--run",
		"--dry-run",
		"--spec",
		"--policy",
		"--canary",
		"--category",
		"--status",
		"--json",
		"--verbose",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentAPISec_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForAPISec(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_apisec_cli_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-apisec-test",
		Name:      "CLI APISec Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-apisec-test",
		Ref:       "ASM-CLI-API-01",
		ClientID:  client.ID,
		Name:      "CLI APISec Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-api-1",
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
			ID:                  "auth-cli-api-1",
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

func TestCLI_AssessmentAPISec_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("dry run must NOT send any HTTP requests to target, got %s", r.URL.Path)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForAPISec(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--dry-run"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run, got %d (err: %s)", code, errOut)
	}
	if !strings.Contains(out, "OWASP API SECURITY PLAN (DRY-RUN)") {
		t.Errorf("expected plan output in dry run, got: %s", out)
	}
	if !strings.Contains(out, "PREREQUISITE ASSESSMENT") {
		t.Errorf("expected prerequisite assessment in plan, got: %s", out)
	}
}

func TestCLI_AssessmentAPISec_ActiveRun_MissingAuthRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForAPISec(t, "https://api.example.com", false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--run"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected security refusal for missing auth, got: %s", errOut)
	}
}

func TestCLI_AssessmentAPISec_ActiveRun_MockExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true") // Credentialed wildcard CORS -> VERIFIED
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok","items":[]}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForAPISec(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--run", "--verbose", "--allow-loopback"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for active run, got %d (err: %s)", code, errOut)
	}
	if !strings.Contains(out, "OWASP API SECURITY TOP 10") {
		t.Errorf("expected results banner, got: %s", out)
	}
}

func TestCLI_AssessmentAPISec_ViewPastResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForAPISec(t, ts.URL, true)
	defer cleanup()

	// Run assessment
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--run", "--allow-loopback"})
	})
	if code != 0 {
		t.Fatalf("failed initial run: %s", errOut)
	}

	// Query past results
	code2, out2, _ := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--status", "VERIFIED", "--json"})
	})
	if code2 != 0 {
		t.Fatalf("failed to query past results, exit code %d", code2)
	}

	var resp struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal([]byte(out2), &resp); err != nil {
		t.Fatalf("expected valid JSON object of past results, got error: %v\nOutput: %s", err, out2)
	}
	if len(resp.Results) == 0 {
		t.Errorf("expected at least 1 verified past result, got 0")
	}
}

func TestCLI_AssessmentCreate_WithEngineType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-cli-create-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "assessments.db")
	t.Setenv("FELIX_DB_PATH", dbPath)

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := assessment.Client{
		ID:        "client-type-test",
		Name:      "Type Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(&client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// 1. Create with --type API_SECURITY
	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentCreate([]string{
			"--client", client.ID,
			"--name", "API Assessment",
			"--target", "https://api.example.com",
			"--type", "API_SECURITY",
			"--json",
		})
	})
	if code != 0 {
		t.Fatalf("failed to create assessment with --type API_SECURITY: %s", errOut)
	}

	var created assessment.Assessment
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if created.AssessmentType != assessment.AssessmentTypeAPISecurity {
		t.Errorf("expected AssessmentType %s, got %s", assessment.AssessmentTypeAPISecurity, created.AssessmentType)
	}

	// 2. Create with --type cloud_security (case-insensitive alias normalization)
	code2, out2, errOut2 := captureStdoutStderr(func() int {
		return runAssessmentCreate([]string{
			"--client", client.ID,
			"--name", "Cloud Assessment",
			"--target", "https://cloud.example.com",
			"--type", "cloud_security",
			"--json",
		})
	})
	if code2 != 0 {
		t.Fatalf("failed to create assessment with --type cloud_security: %s", errOut2)
	}
	var created2 assessment.Assessment
	if err := json.Unmarshal([]byte(out2), &created2); err != nil {
		t.Fatalf("failed to unmarshal JSON output 2: %v", err)
	}
	if created2.AssessmentType != assessment.AssessmentTypeCloudSecurity {
		t.Errorf("expected AssessmentType %s, got %s", assessment.AssessmentTypeCloudSecurity, created2.AssessmentType)
	}

	// 3. Create with invalid type -> returns 2 with error
	code3, _, errOut3 := captureStdoutStderr(func() int {
		return runAssessmentCreate([]string{
			"--client", client.ID,
			"--name", "Invalid Assessment",
			"--target", "https://example.com",
			"--type", "non_existent_engine_xyz",
		})
	})
	if code3 != 2 {
		t.Errorf("expected exit code 2 for invalid type, got %d", code3)
	}
	if !strings.Contains(errOut3, "unsupported --type") {
		t.Errorf("expected error message to mention unsupported --type, got: %s", errOut3)
	}
}

func TestCLI_AssessmentAPISec_ActiveRun_JSON_CleanOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok","items":[]}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForAPISec(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--run", "--json", "--allow-loopback"})
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
