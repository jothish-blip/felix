package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

func createReproductionTestScanJSON(t *testing.T, filePath string) {
	t.Helper()

	f1 := report.Finding{
		ID:          "FND-AUTH-001",
		Title:       "Public Token Leak",
		Category:    "token-leak",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://target.example.com",
		Endpoint:    "/static/bundle.js",
		Method:      "GET",
		Evidence:    "ADMIN_API_KEY_TOKEN",
		Fingerprint: "fp-auth-001",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "CONFIRMED_VULNERABILITY",
		},
	}

	f2 := report.Finding{
		ID:          "FND-ROUTE-002",
		Title:       "Admin Route Exposure",
		Category:    "shadow-route",
		Severity:    report.SeverityCritical,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://target.example.com",
		Endpoint:    "/api/v2/admin/status",
		Method:      "GET",
		Evidence:    "Database connected: postgresql://",
		Fingerprint: "fp-route-002",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "CONFIRMED_VULNERABILITY",
		},
	}

	attackPath := report.AttackPathSummary{
		ID:                "AP-TEST-CHAIN-01",
		Title:             "Token Leak to Admin Route",
		TargetAsset:       "Admin Database",
		Confidence:        "HIGH",
		Status:            "CONFIRMED",
		NodeIDs:           []string{"FND-AUTH-001", "FND-ROUTE-002"},
		CombinedRiskLevel: "CRITICAL",
		CombinedRiskScore: 85,
	}

	rep := report.Report{
		Version:          "2.0",
		Target:           "https://target.example.com",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		CompletionStatus: "COMPLETED",
		Findings:         []report.Finding{f1, f2},
		AttackPaths:      []report.AttackPathSummary{attackPath},
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal scan JSON: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write scan JSON: %v", err)
	}
}

func TestCLIReport_ReproduceChain_Valid(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createReproductionTestScanJSON(t, scanFile)

	scriptOut := filepath.Join(tempDir, "reproduce_test.sh")

	code := runReport([]string{scanFile, "--reproduce-chain", "AP-TEST-CHAIN-01", "--output", scriptOut, "--silent"})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for reproduction script export, got %d", code)
	}

	content, err := os.ReadFile(scriptOut)
	if err != nil {
		t.Fatalf("reproduction script not written: %v", err)
	}

	scriptStr := string(content)
	if !strings.HasPrefix(scriptStr, "#!/usr/bin/env bash") {
		t.Errorf("expected script to start with #!/usr/bin/env bash")
	}
	if !strings.Contains(scriptStr, "TARGET_ORIGIN") {
		t.Errorf("expected script to include TARGET_ORIGIN validation")
	}
	if !strings.Contains(scriptStr, "AP-TEST-CHAIN-01") {
		t.Errorf("expected script to reference chain ID AP-TEST-CHAIN-01")
	}
	if !strings.Contains(scriptStr, "/static/bundle.js") {
		t.Errorf("expected script to reference /static/bundle.js")
	}
	if !strings.Contains(scriptStr, "/api/v2/admin/status") {
		t.Errorf("expected script to reference /api/v2/admin/status")
	}
}

func TestCLIReport_ReproduceChain_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createReproductionTestScanJSON(t, scanFile)

	scriptOut := filepath.Join(tempDir, "reproduce_nonexistent.sh")

	code := runReport([]string{scanFile, "--reproduce-chain", "AP-NONEXISTENT", "--output", scriptOut, "--silent"})
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (%d) when chain ID not found, got %d", clierror.ExitOperational, code)
	}

	if _, err := os.Stat(scriptOut); !os.IsNotExist(err) {
		t.Errorf("expected script to not be written when chain ID is not found")
	}
}

func TestCLIReport_ReproduceChain_OverwriteProtection(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createReproductionTestScanJSON(t, scanFile)

	scriptOut := filepath.Join(tempDir, "reproduce_existing.sh")
	if err := os.WriteFile(scriptOut, []byte("echo initial\n"), 0755); err != nil {
		t.Fatalf("failed to pre-create script: %v", err)
	}

	// 1. Without --overwrite should fail
	codeNoOverwrite := runReport([]string{scanFile, "--reproduce-chain", "AP-TEST-CHAIN-01", "--output", scriptOut, "--silent"})
	if codeNoOverwrite != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (%d) on existing file without --overwrite, got %d", clierror.ExitOperational, codeNoOverwrite)
	}

	// Verify content unchanged
	preContent, _ := os.ReadFile(scriptOut)
	if string(preContent) != "echo initial\n" {
		t.Errorf("expected file not to be overwritten")
	}

	// 2. With --overwrite should succeed
	codeOverwrite := runReport([]string{scanFile, "--reproduce-chain", "AP-TEST-CHAIN-01", "--output", scriptOut, "--overwrite", "--silent"})
	if codeOverwrite != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) on existing file with --overwrite, got %d", codeOverwrite)
	}

	postContent, _ := os.ReadFile(scriptOut)
	if !strings.Contains(string(postContent), "AP-TEST-CHAIN-01") {
		t.Errorf("expected file to be replaced with generated reproduction script")
	}
}
