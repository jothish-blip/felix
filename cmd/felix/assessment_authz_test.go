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
	"felix/pkg/authz"
)

func setupTestAssessmentForAuthz(t *testing.T, targetURL string, approveAuth bool) (*assessment.Assessment, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_authz_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	client := assessment.Client{
		ID:        "client-cli-authz-test",
		Name:      "CLI Authz Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-cli-authz-test",
		Ref:       "ASM-CLI-AUTHZ-01",
		ClientID:  client.ID,
		Name:      "CLI Authz Verification Test",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-cli-authz-1",
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
			ID:                  "auth-cli-authz-1",
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

func createTestPolicyFile(t *testing.T, dir string) string {
	t.Helper()
	policy := authz.AuthzPolicy{
		AssessmentRef:    "ASM-CLI-AUTHZ-01",
		AuthorizationDoc: "DOC-AUTHZ-01",
		AllowWriteTests:  false,
		Identities: map[string]authz.TestIdentity{
			"admin": {
				Alias:          "admin",
				Role:           "admin",
				PrivilegeLevel: 5,
				Headers:        map[string]string{"Authorization": "Bearer admin_tok"},
			},
			"user": {
				Alias:          "user",
				Role:           "user",
				PrivilegeLevel: 1,
				Headers:        map[string]string{"Authorization": "Bearer user_tok"},
			},
		},
		Endpoints: []authz.EndpointRule{
			{
				Pattern:      "/api/admin/system",
				Method:       "GET",
				AllowedRoles: []string{"admin"},
				DeniedRoles:  []string{"user"},
				AdminOnly:    true,
			},
		},
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}

	pPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pPath, data, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	return pPath
}

func TestCLI_AssessmentAuthz_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssessmentAuthz([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	expectedStrings := []string{
		"Usage: felix assessment authz",
		"--policy",
		"--run",
		"--dry-run",
		"--allow-loopback",
		"--allow-private",
		"--json",
	}
	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help text to contain %q", exp)
		}
	}
}

func TestCLI_AssessmentAuthz_MissingRef_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAuthz([]string{})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when assessment ref is missing, got %d", code)
	}
	if !strings.Contains(errOut, "assessment ID or Ref is required") {
		t.Errorf("expected error message for missing assessment ref, got %q", errOut)
	}
}

func TestCLI_AssessmentAuthz_DryRun_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := createTestPolicyFile(t, tmpDir)

	asm, cleanup := setupTestAssessmentForAuthz(t, "https://example.com", false)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentAuthz([]string{asm.Ref, "--dry-run", "--policy", policyPath, "--json"})
	})

	if code != 0 {
		t.Fatalf("expected dry-run --json to exit 0, got %d, errOut: %s", code, errOut)
	}

	var planMap map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &planMap); err != nil {
		t.Fatalf("expected valid JSON output from dry-run --json, got error: %v, raw: %s", err, out)
	}

	if planMap["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %q, got %v", asm.Ref, planMap["assessment_ref"])
	}
	planned, ok := planMap["planned_tests"].([]interface{})
	if !ok || len(planned) == 0 {
		t.Errorf("expected non-empty planned_tests in JSON, got %v", planMap["planned_tests"])
	}
}

func TestCLI_AssessmentAuthz_ActiveRun_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := createTestPolicyFile(t, tmpDir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "admin_tok") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"admin_system":"healthy"}`)
			return
		}
		// For standard user: deny
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	asm, cleanup := setupTestAssessmentForAuthz(t, ts.URL, true)
	defer cleanup()

	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentAuthz([]string{
			asm.Ref,
			"--policy", policyPath,
			"--run",
			"--allow-loopback",
			"--json",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for authorized active authz assessment, got %d, errOut: %s", code, errOut)
	}

	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("expected JSON output starting with '{', got prefix: %s", out[:min(len(out), 80)])
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonMap); err != nil {
		t.Fatalf("failed to parse JSON from --run --json output: %v\nOutput was: %s", err, out)
	}

	if jsonMap["assessment_ref"] != asm.Ref {
		t.Errorf("expected assessment_ref %q, got %v", asm.Ref, jsonMap["assessment_ref"])
	}
}
