package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runFelixWithEnv executes the felix binary with isolated environment variables.
func runFelixWithEnv(t *testing.T, env []string, args ...string) (string, int) {
	binPath := getFelixBinPath(t)
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.ExitCode()
		}
		return out, -1
	}
	return out, 0
}

func TestAssessment_CLI_EndToEndLifecycle(t *testing.T) {
	// 1. Setup isolated environment
	tmpDir, err := os.MkdirTemp("", "felix_cli_asm_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	env := []string{
		"FELIX_DIR=" + tmpDir,
	}

	// 2. Setup mock target server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<html>
			<head><title>Test Application</title></head>
			<body>
				<a href="/public">Public Page</a>
				<script>
					const fake_api = "AKIAIOSFODNN7EXAMPLE";
				</script>
			</body>
			</html>
		`)
	}))
	defer server.Close()

	// 3. Client Add
	out, code := runFelixWithEnv(t, env, "client", "add", "--name", "Acme Corporation", "--notes", "Enterprise", "--json")
	if code != 0 {
		t.Fatalf("client add failed (code %d): %s", code, out)
	}

	var clientData struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &clientData); err != nil || clientData.ID == "" {
		t.Fatalf("failed to parse client add output: %v, raw: %s", err, out)
	}
	clientID := clientData.ID

	// 4. Client List
	out, code = runFelixWithEnv(t, env, "client", "list")
	if code != 0 || !strings.Contains(out, "Acme Corporation") {
		t.Fatalf("client list expected Acme Corporation: code=%d, out=%s", code, out)
	}

	// 5. Client Show
	out, code = runFelixWithEnv(t, env, "client", "show", clientID)
	if code != 0 || !strings.Contains(out, clientID) {
		t.Fatalf("client show failed: code=%d, out=%s", code, out)
	}

	// 6. Assessment Create (with target)
	out, code = runFelixWithEnv(t, env, "assessment", "create",
		"--client", clientID,
		"--name", "Web Security Audit Q1",
		"--target", server.URL,
		"--scope-mode", "same-origin",
		"--json",
	)
	if code != 0 {
		t.Fatalf("assessment create failed (code %d): %s", code, out)
	}

	var asmData struct {
		ID  string `json:"id"`
		Ref string `json:"ref"`
	}
	if err := json.Unmarshal([]byte(out), &asmData); err != nil || asmData.Ref == "" {
		t.Fatalf("failed to parse assessment create output: %v, raw: %s", err, out)
	}
	asmRef := asmData.Ref

	// 7. Assessment Show
	out, code = runFelixWithEnv(t, env, "assessment", "show", asmRef)
	if code != 0 || !strings.Contains(out, asmRef) || !strings.Contains(out, "PENDING") {
		t.Fatalf("assessment show unexpected output: code=%d, out=%s", code, out)
	}

	// 8. Assessment Scope Add
	out, code = runFelixWithEnv(t, env, "assessment", "scope", "add", asmRef, "--rule", "subdomains:example.com")
	if code != 0 || !strings.Contains(out, "[+] Added scope rule") {
		t.Fatalf("assessment scope add failed: code=%d, out=%s", code, out)
	}

	// 9. Assessment Exclude Add
	out, code = runFelixWithEnv(t, env, "assessment", "exclude", "add", asmRef,
		"--type", "PATH_PREFIX",
		"--pattern", "/admin",
		"--reason", "Out of testing scope",
	)
	if code != 0 || !strings.Contains(out, "[+] Added exclusion") {
		t.Fatalf("assessment exclude add failed: code=%d, out=%s", code, out)
	}

	// 10. Attempt Run Before Authorization -> Must Fail Closed
	out, code = runFelixWithEnv(t, env, "assessment", "run", asmRef)
	if code == 0 || !strings.Contains(out, "security refusal") {
		t.Fatalf("expected security refusal running unauthorized assessment, got code=%d, out=%s", code, out)
	}

	// 11. Authorize Assessment
	out, code = runFelixWithEnv(t, env, "assessment", "authorize", asmRef,
		"--authorizer", "Jane Doe",
		"--role", "Chief Information Security Officer",
		"--reference", "AUTH-DOC-2026-001",
		"--valid-days", "30",
	)
	if code != 0 || !strings.Contains(out, "APPROVED") {
		t.Fatalf("assessment authorize failed: code=%d, out=%s", code, out)
	}

	// 12. Run Assessment -> Must Succeed Now!
	reportHTML := filepath.Join(tmpDir, "audit_report.html")
	reportJSON := filepath.Join(tmpDir, "audit_report.json")
	out, code = runFelixWithEnv(t, env, "assessment", "run", asmRef,
		"--concurrency", "2",
		"--timeout", "5s",
		"--html", reportHTML,
		"--json", reportJSON,
	)
	if code != 0 || !strings.Contains(out, "ASSESSMENT RUN COMPLETE") {
		t.Fatalf("assessment run failed: code=%d, out=%s", code, out)
	}

	// Verify report files created on disk
	if _, err := os.Stat(reportHTML); os.IsNotExist(err) {
		t.Errorf("expected HTML report at %s", reportHTML)
	}
	if _, err := os.Stat(reportJSON); os.IsNotExist(err) {
		t.Errorf("expected JSON report at %s", reportJSON)
	}

	// 13. Assessment Findings inspection
	out, code = runFelixWithEnv(t, env, "assessment", "findings", asmRef)
	if code != 0 {
		t.Fatalf("assessment findings failed: code=%d, out=%s", code, out)
	}

	// 14. Assessment Reports inspection
	out, code = runFelixWithEnv(t, env, "assessment", "reports", asmRef)
	if code != 0 || !strings.Contains(out, "HTML") {
		t.Fatalf("assessment reports failed: code=%d, out=%s", code, out)
	}

	// 14b. Assessment Attack-Surface Inventory inspection
	out, code = runFelixWithEnv(t, env, "assessment", "inventory", asmRef)
	if code != 0 || !strings.Contains(out, "ATTACK-SURFACE INVENTORY") {
		t.Fatalf("assessment inventory failed: code=%d, out=%s", code, out)
	}

	// 14c. Assessment Inventory JSON inspection
	out, code = runFelixWithEnv(t, env, "assessment", "inventory", asmRef, "--json")
	if code != 0 || !strings.Contains(out, "assets") || !strings.Contains(out, "relations") {
		t.Fatalf("assessment inventory JSON failed: code=%d, out=%s", code, out)
	}

	// 15. Assessment Cancel
	out, code = runFelixWithEnv(t, env, "assessment", "cancel", asmRef)
	if code != 0 || !strings.Contains(out, "CANCELLED") {
		t.Fatalf("assessment cancel failed: code=%d, out=%s", code, out)
	}

	// 16. Client Archive
	out, code = runFelixWithEnv(t, env, "client", "archive", clientID)
	if code != 0 || !strings.Contains(out, "archived successfully") {
		t.Fatalf("client archive failed: code=%d, out=%s", code, out)
	}
}
