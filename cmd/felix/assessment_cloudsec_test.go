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

func TestCLI_AssessmentCloudSec_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment cloudsec",
		"--run",
		"--dry-run",
		"--mode",
		"--provider",
		"--credentials",
		"--service",
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

func TestCLI_AssessmentCloudSec_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func setupTestAssessmentForCloudSec(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_cloudsec_cli_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-cloudsec-test",
		Name:      "CLI CloudSec Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-cloudsec-test",
		Ref:       "ASM-CLI-CLOUD-01",
		ClientID:  client.ID,
		Name:      "CLI CloudSec Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-cloud-1",
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
			ID:                  "auth-cli-cloud-1",
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

func TestCLI_AssessmentCloudSec_DryRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("dry run must NOT send network requests, got %s", r.URL.Path)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForCloudSec(t, ts.URL, false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--dry-run", "--mode", "external"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run, got %d (err: %s)", code, errOut)
	}
	if !strings.Contains(out, "REAL CLOUD SECURITY ASSESSMENT PLAN (DRY-RUN)") {
		t.Errorf("expected plan banner, got: %s", out)
	}
	if !strings.Contains(out, "PLANNED CLOUD SECURITY CHECKS") {
		t.Errorf("expected planned checks section, got: %s", out)
	}
}

func TestCLI_AssessmentCloudSec_ActiveRun_MissingAuthRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForCloudSec(t, "https://mybucket.s3.amazonaws.com", false)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--run", "--mode", "external"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Security refusal: no authorization record found") {
		t.Errorf("expected security refusal for missing auth, got: %s", errOut)
	}
}

func TestCLI_AssessmentCloudSec_CredentialedMode_MissingCredsRefused(t *testing.T) {
	asm, cleanup := setupTestAssessmentForCloudSec(t, "https://example.com", true)
	defer cleanup()

	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--run", "--mode", "credentialed"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 when credentialed mode lacks --credentials, got %d", code)
	}
	if !strings.Contains(errOut, "Credentialed mode requires --credentials") {
		t.Errorf("expected credential error message, got: %s", errOut)
	}
}

func TestCLI_AssessmentCloudSec_ExternalRun_MockExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name></ListBucketResult>`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForCloudSec(t, ts.URL+"/s3-test", true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--run", "--mode", "external", "--verbose", "--allow-loopback"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for external cloudsec run, got %d (err: %s)", code, errOut)
	}
	if !strings.Contains(out, "REAL CLOUD SECURITY REPORT") && !strings.Contains(out, "CLOUD SECURITY FINDINGS") {
		t.Errorf("expected results banner, got: %s", out)
	}
}

func TestCLI_AssessmentCloudSec_ViewPastResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>test-bucket</Name></ListBucketResult>`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForCloudSec(t, ts.URL+"/s3-test", true)
	defer cleanup()

	// Initial execution
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--run", "--mode", "external", "--allow-loopback"})
	})
	if code != 0 {
		t.Fatalf("failed initial run: %s", errOut)
	}

	// Query past results via JSON
	code2, out2, _ := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--json"})
	})
	if code2 != 0 {
		t.Fatalf("failed to query past results, exit code %d", code2)
	}

	var resp struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal([]byte(out2), &resp); err != nil {
		t.Fatalf("expected valid JSON object with results, got error: %v\nOutput: %s", err, out2)
	}
	if len(resp.Results) == 0 {
		t.Errorf("expected at least 1 recorded cloudsec result, got 0")
	}
}

func TestCLI_AssessmentCloudSec_CleanJSON_OnRun(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>test-bucket</Name></ListBucketResult>`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForCloudSec(t, ts.URL+"/s3-test", true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentCloudSec([]string{asm.Ref, "--run", "--mode", "external", "--allow-loopback", "--json"})
	})
	if code != 0 {
		t.Fatalf("expected exit code 0 for cloudsec run with --json, got %d (err: %s)", code, errOut)
	}

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Fatalf("cloudsec CLI output is polluted with banner text: %q", out)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("failed to parse cloudsec JSON output: %v\nOutput: %s", err, out)
	}

	if parsed["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %s, got %v", asm.Ref, parsed["assessment_ref"])
	}
}
