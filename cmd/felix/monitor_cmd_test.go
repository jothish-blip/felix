package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeTestProfile(t *testing.T, dir string, content string) string {
	t.Helper()
	profilePath := filepath.Join(dir, "felix.target.yml")
	if err := os.WriteFile(profilePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test profile: %v", err)
	}
	return profilePath
}

func TestMonitorCmd_Help(t *testing.T) {
	// Top-level monitor help
	if code := runMonitor([]string{"--help"}); code != 0 {
		t.Fatalf("expected exit 0 for --help, got %d", code)
	}
	if code := runMonitor([]string{"help"}); code != 0 {
		t.Fatalf("expected exit 0 for help, got %d", code)
	}
	if code := runMonitor([]string{}); code != 0 {
		t.Fatalf("expected exit 0 for empty args, got %d", code)
	}

	// Subcommand help
	subcommands := []string{"snapshot", "diff", "status", "baseline", "test-webhook"}
	for _, sub := range subcommands {
		if code := runMonitor([]string{sub, "--help"}); code != 0 {
			t.Fatalf("expected exit 0 for %s --help, got %d", sub, code)
		}
		if code := runMonitor([]string{sub, "-h"}); code != 0 {
			t.Fatalf("expected exit 0 for %s -h, got %d", sub, code)
		}
	}
}

func TestMonitorCmd_UnknownSubcommand(t *testing.T) {
	code := runMonitor([]string{"nonexistent-subcommand"})
	if code != 2 {
		t.Fatalf("expected operational error exit code 2, got %d", code)
	}
}

func TestMonitorCmd_MissingOrInvalidProfile(t *testing.T) {
	// 1. Missing --profile flag
	if code := runMonitor([]string{"snapshot"}); code != 2 {
		t.Fatalf("expected exit 2 when --profile is missing, got %d", code)
	}

	// 2. Missing profile path argument
	if code := runMonitor([]string{"snapshot", "--profile"}); code != 2 {
		t.Fatalf("expected exit 2 when --profile has no argument, got %d", code)
	}

	// 3. Non-existent profile file
	if code := runMonitor([]string{"snapshot", "--profile", "non_existent_file_9999.yml"}); code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile, got %d", code)
	}
	if code := runMonitor([]string{"diff", "--profile", "non_existent_file_9999.yml"}); code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile in diff, got %d", code)
	}
	if code := runMonitor([]string{"status", "--profile", "non_existent_file_9999.yml"}); code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile in status, got %d", code)
	}
	if code := runMonitor([]string{"baseline", "--profile", "non_existent_file_9999.yml"}); code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile in baseline, got %d", code)
	}
	if code := runMonitor([]string{"test-webhook", "--profile", "non_existent_file_9999.yml"}); code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile in test-webhook, got %d", code)
	}
}

func TestMonitorCmd_Snapshot_Workflow(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Snapshot Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
monitoring:
  enabled: true
  retain_snapshots: 10
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// 1. First snapshot: captures snapshot and initializes baseline
	code := runMonitor([]string{
		"snapshot",
		"--profile", profilePath,
		"--state-dir", stateDir,
	})
	if code != 0 {
		t.Fatalf("expected exit 0 for initial snapshot, got %d", code)
	}

	// 2. Snapshot with --json flag
	code = runMonitor([]string{
		"snapshot",
		"--profile=" + profilePath,
		"--state-dir=" + stateDir,
		"--json",
	})
	if code != 0 {
		t.Fatalf("expected exit 0 for json snapshot, got %d", code)
	}

	// 3. Snapshot with positional profile argument and --quiet
	code = runMonitor([]string{
		"snapshot",
		profilePath,
		"--state-dir", stateDir,
		"--quiet",
	})
	if code != 0 {
		t.Fatalf("expected exit 0 for quiet snapshot, got %d", code)
	}

	// Verify state directory contents
	targetDir := filepath.Join(stateDir, "CLI_Snapshot_Test_Target")
	baselineFile := filepath.Join(targetDir, "baseline.json")
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		t.Fatalf("expected baseline.json to exist at %s", baselineFile)
	}

	snapshotsDir := filepath.Join(targetDir, "snapshots")
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil || len(entries) < 3 {
		t.Fatalf("expected at least 3 snapshot files in %s, got %d (err: %v)", snapshotsDir, len(entries), err)
	}
}

func TestMonitorCmd_Diff_Workflow(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Diff Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
  allow_cross_tenant_checks: true
tenants:
  - id: "tenant_alpha"
    identity: "alpha@example.corp"
    resource_ids:
      - "res_001"
  - id: "tenant_beta"
    identity: "beta@example.corp"
    resource_ids: []
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "tenant_beta"
      resource_owner_tenant: "tenant_alpha"
      resource_id: "res_001"
      path: "/api/v1/users/res_001"
      method: "GET"
monitoring:
  enabled: true
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// Initialize baseline snapshot
	code := runMonitor([]string{"snapshot", "--profile", profilePath, "--state-dir", stateDir, "--quiet"})
	if code != 0 {
		t.Fatalf("expected snapshot exit 0, got %d", code)
	}

	// Run diff immediately (should detect zero drift against baseline)
	code = runMonitor([]string{"diff", "--profile", profilePath, "--state-dir", stateDir})
	if code != 0 {
		t.Fatalf("expected diff exit 0, got %d", code)
	}

	// Run diff with --json
	code = runMonitor([]string{"diff", "--profile", profilePath, "--state-dir", stateDir, "--json"})
	if code != 0 {
		t.Fatalf("expected diff --json exit 0, got %d", code)
	}

	// Introduce a new route comparison in profile
	updatedProfile := `version: 1
target:
  name: "CLI Diff Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
  allow_cross_tenant_checks: true
tenants:
  - id: "tenant_alpha"
    identity: "alpha@example.corp"
    resource_ids:
      - "res_001"
      - "res_002"
  - id: "tenant_beta"
    identity: "beta@example.corp"
    resource_ids: []
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "tenant_beta"
      resource_owner_tenant: "tenant_alpha"
      resource_id: "res_001"
      path: "/api/v1/users/res_001"
      method: "GET"
    - requester_tenant: "tenant_beta"
      resource_owner_tenant: "tenant_alpha"
      resource_id: "res_002"
      path: "/api/v1/tenants/res_002/info"
      method: "GET"
monitoring:
  enabled: true
`
	writeTestProfile(t, tempDir, updatedProfile)

	// Capture updated snapshot
	code = runMonitor([]string{"snapshot", "--profile", profilePath, "--state-dir", stateDir, "--quiet"})
	if code != 0 {
		t.Fatalf("expected snapshot exit 0, got %d", code)
	}

	// Run diff with --notify
	code = runMonitor([]string{"diff", "--profile", profilePath, "--state-dir", stateDir, "--notify"})
	if code != 0 {
		t.Fatalf("expected diff --notify exit 0, got %d", code)
	}
}

func TestMonitorCmd_Status_Workflow(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Status Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
monitoring:
  enabled: true
  webhooks:
    - id: "slack-channel"
      provider: "slack"
      url: "https://hooks.slack.com/services/TEST/1/2"
      enabled: true
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// 1. Status before any snapshot
	code := runMonitor([]string{"status", "--profile", profilePath, "--state-dir", stateDir})
	if code != 0 {
		t.Fatalf("expected status exit 0 before snapshot, got %d", code)
	}

	// 2. Snapshot
	code = runMonitor([]string{"snapshot", "--profile", profilePath, "--state-dir", stateDir, "--quiet"})
	if code != 0 {
		t.Fatalf("expected snapshot exit 0, got %d", code)
	}

	// 3. Status with text output
	code = runMonitor([]string{"status", "--profile", profilePath, "--state-dir", stateDir})
	if code != 0 {
		t.Fatalf("expected status exit 0 after snapshot, got %d", code)
	}

	// 4. Status with JSON output
	code = runMonitor([]string{"status", "--profile", profilePath, "--state-dir", stateDir, "--json"})
	if code != 0 {
		t.Fatalf("expected status --json exit 0, got %d", code)
	}
}

func TestMonitorCmd_Baseline_InspectionAndReset(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Baseline Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
monitoring:
  enabled: true
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// Baseline when no snapshots exist -> should fail with exit 2
	code := runMonitor([]string{"baseline", "--profile", profilePath, "--state-dir", stateDir})
	if code != 2 {
		t.Fatalf("expected exit 2 when baseline is not yet established, got %d", code)
	}

	// Capture initial snapshot
	code = runMonitor([]string{"snapshot", "--profile", profilePath, "--state-dir", stateDir, "--quiet"})
	if code != 0 {
		t.Fatalf("expected snapshot exit 0, got %d", code)
	}

	// Baseline inspection
	code = runMonitor([]string{"baseline", "--profile", profilePath, "--state-dir", stateDir})
	if code != 0 {
		t.Fatalf("expected baseline inspection exit 0, got %d", code)
	}

	// Baseline reset with explicit reason
	code = runMonitor([]string{
		"baseline",
		"--profile", profilePath,
		"--state-dir", stateDir,
		"--reset",
		"--reason", "Quarterly scheduled baseline rotation",
	})
	if code != 0 {
		t.Fatalf("expected baseline reset exit 0, got %d", code)
	}
}

func TestMonitorCmd_TestWebhook_Dispatch(t *testing.T) {
	received := make(chan string, 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		received <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Webhook Test Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
monitoring:
  enabled: true
  webhooks:
    - id: "slack-test"
      provider: "slack"
      url: "` + srv.URL + `/services/slack"
      enabled: true
      allow_insecure_http: true
      allow_loopback: true
    - id: "discord-test"
      provider: "discord"
      url: "` + srv.URL + `/api/webhooks/discord"
      enabled: true
      allow_insecure_http: true
      allow_loopback: true
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// 1. Test Slack webhook dispatch
	code := runMonitor([]string{
		"test-webhook",
		"--profile", profilePath,
		"--state-dir", stateDir,
		"--provider", "slack",
	})
	if code != 0 {
		t.Fatalf("expected test-webhook exit 0 for slack, got %d", code)
	}

	// 2. Test Discord webhook dispatch
	code = runMonitor([]string{
		"test-webhook",
		"--profile", profilePath,
		"--state-dir", stateDir,
		"--provider", "discord",
	})
	if code != 0 {
		t.Fatalf("expected test-webhook exit 0 for discord, got %d", code)
	}

	// Verify both webhooks were hit
	if len(received) < 2 {
		t.Fatalf("expected at least 2 webhooks delivered, got %d", len(received))
	}

	// 3. Test Insecure Destination Rejection
	insecureProfile := `version: 1
target:
  name: "Insecure Target"
  base_urls:
    - "https://api.example.com"
monitoring:
  enabled: true
  webhooks:
    - id: "blocked-insecure"
      provider: "slack"
      url: "http://insecure-api.corp/webhook"
      enabled: true
      allow_insecure_http: false
`
	insecurePath := writeTestProfile(t, tempDir, insecureProfile)
	code = runMonitor([]string{
		"test-webhook",
		"--profile", insecurePath,
		"--state-dir", stateDir,
	})
	if code != 2 {
		t.Fatalf("expected operational error exit 2 when insecure HTTP is rejected, got %d", code)
	}
}

func TestMonitorCmd_CheckAliasEquivalence(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	yamlProfile := `version: 1
target:
  name: "CLI Check Alias Target"
  base_urls:
    - "https://api.example.com"
  allowed_hosts:
    - "api.example.com"
safety:
  mode: "non_destructive"
monitoring:
  enabled: true
`
	profilePath := writeTestProfile(t, tempDir, yamlProfile)

	// Baseline snapshot
	if code := runMonitor([]string{"snapshot", "--profile", profilePath, "--state-dir", stateDir, "--quiet"}); code != 0 {
		t.Fatalf("expected snapshot exit 0, got %d", code)
	}

	// 1. Run canonical "diff" with --json
	codeDiff, outDiff, _ := captureStdoutStderr(func() int {
		return runMonitor([]string{"diff", "--profile", profilePath, "--state-dir", stateDir, "--json"})
	})
	if codeDiff != 0 {
		t.Fatalf("expected diff exit 0, got %d", codeDiff)
	}

	// 2. Run alias "check" with --json
	codeCheck, outCheck, _ := captureStdoutStderr(func() int {
		return runMonitor([]string{"check", "--profile", profilePath, "--state-dir", stateDir, "--json"})
	})
	if codeCheck != 0 {
		t.Fatalf("expected check exit 0, got %d", codeCheck)
	}

	// 3. Verify exit codes match
	if codeDiff != codeCheck {
		t.Fatalf("expected identical exit codes, diff got %d, check got %d", codeDiff, codeCheck)
	}

	// 4. Verify outputs parse as valid JSON and both report temporal drift structures
	var diffObj, checkObj map[string]interface{}
	if err := json.Unmarshal([]byte(outDiff), &diffObj); err != nil {
		t.Fatalf("diff JSON unmarshal error: %v (raw: %s)", err, outDiff)
	}
	if err := json.Unmarshal([]byte(outCheck), &checkObj); err != nil {
		t.Fatalf("check JSON unmarshal error: %v (raw: %s)", err, outCheck)
	}

	if _, ok := diffObj["drift_report"]; !ok {
		t.Fatalf("expected drift_report key in diff output")
	}
	if _, ok := checkObj["drift_report"]; !ok {
		t.Fatalf("expected drift_report key in check output")
	}
}
