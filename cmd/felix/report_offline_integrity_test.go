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

// TestCLI_ReportOfflineIntegrity verifies that `felix report <input>` enforces strict data integrity
// and never silently reinterprets corrupt, contradictory, or missing data as clean scans.
func TestCLI_ReportOfflineIntegrity(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Valid canonical export succeeds
	t.Run("Valid canonical report export succeeds", func(t *testing.T) {
		validFile := filepath.Join(tempDir, "valid_scan.json")
		rep := report.BuildReport("https://app.example.com", []report.Finding{
			{
				ID:       "FND-01",
				Title:    "SQL Injection",
				Severity: report.SeverityHigh,
				Target:   "https://app.example.com",
				Endpoint: "/search",
			},
		})
		rep.CompletionStatus = "COMPLETED"
		rep.Timestamp = time.Now().UTC().Format(time.RFC3339)
		_ = report.WriteJSON(rep, validFile)

		outFile := filepath.Join(tempDir, "valid_out.html")
		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{validFile, "--html", outFile, "-s"})
		})
		if code != clierror.ExitSuccess && code != clierror.ExitSecurityFail {
			t.Fatalf("expected 0 or 1 for valid report, got %d (stderr: %s)", code, errOut)
		}
		if _, err := os.Stat(outFile); os.IsNotExist(err) {
			t.Errorf("expected output HTML report to be created")
		}
	})

	// 2. Valid genuinely zero-finding assessment succeeds
	t.Run("Valid genuinely zero-finding assessment succeeds", func(t *testing.T) {
		cleanFile := filepath.Join(tempDir, "clean_scan.json")
		rep := report.BuildReport("https://clean.example.com", nil)
		rep.CompletionStatus = "COMPLETED"
		rep.Timestamp = time.Now().UTC().Format(time.RFC3339)
		_ = report.WriteJSON(rep, cleanFile)

		outFile := filepath.Join(tempDir, "clean_out.html")
		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{cleanFile, "--html", outFile, "-s"})
		})
		if code != clierror.ExitSuccess {
			t.Fatalf("expected ExitSuccess (0) for clean scan, got %d (stderr: %s)", code, errOut)
		}
		if _, err := os.Stat(outFile); os.IsNotExist(err) {
			t.Errorf("expected clean output HTML report to be created")
		}
	})

	// 3. Empty JSON or missing target scope is rejected with exit code 2
	t.Run("Missing target scope rejected", func(t *testing.T) {
		missingTargetFile := filepath.Join(tempDir, "missing_target.json")
		_ = os.WriteFile(missingTargetFile, []byte(`{"version":"2.0.0","findings":[]}`), 0644)

		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{missingTargetFile, "-s"})
		})
		if code != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for missing target, got %d", code)
		}
		if !strings.Contains(errOut, "missing assessment target") {
			t.Errorf("expected error mentioning missing target, got: %s", errOut)
		}
	})

	// 4. Contradictory data: Summary claims 3 critical findings, but findings list is empty
	t.Run("Summary claims findings but collection is empty", func(t *testing.T) {
		corruptFile := filepath.Join(tempDir, "corrupt_omitted.json")
		rep := report.Report{
			Target:           "https://app.example.com",
			CompletionStatus: "COMPLETED",
			Summary: report.Summary{
				TotalFindings: 3,
				CriticalCount: 3,
			},
			Findings: nil, // Findings missing!
		}
		data, _ := json.Marshal(rep)
		_ = os.WriteFile(corruptFile, data, 0644)

		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{corruptFile, "-s"})
		})
		if code != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for omitted findings, got %d", code)
		}
		if !strings.Contains(errOut, "claims 3 finding(s), but findings collection is empty") {
			t.Errorf("expected error explaining findings omission, got: %s", errOut)
		}
	})

	// 5. Contradictory severity breakdown rejected
	t.Run("Contradictory severity breakdown rejected", func(t *testing.T) {
		contradictoryFile := filepath.Join(tempDir, "contradictory.json")
		rep := report.Report{
			Target:           "https://app.example.com",
			CompletionStatus: "COMPLETED",
			Summary: report.Summary{
				TotalFindings: 1,
				CriticalCount: 1, // Claims Critical
			},
			Findings: []report.Finding{
				{
					ID:       "fnd-low",
					Severity: report.SeverityLow, // But finding is Low!
				},
			},
		}
		data, _ := json.Marshal(rep)
		_ = os.WriteFile(contradictoryFile, data, 0644)

		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{contradictoryFile, "-s"})
		})
		if code != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for contradictory severities, got %d", code)
		}
		if !strings.Contains(errOut, "critical finding count mismatch") {
			t.Errorf("expected error explaining severity mismatch, got: %s", errOut)
		}
	})

	// 6. Malformed JSON rejected safely with exit code 2
	t.Run("Malformed JSON rejected", func(t *testing.T) {
		malformedFile := filepath.Join(tempDir, "malformed.json")
		_ = os.WriteFile(malformedFile, []byte(`{"target": "https://example.com", "findings": [`), 0644)

		code, _, errOut := captureStdoutStderr(func() int {
			return runReport([]string{malformedFile, "-s"})
		})
		if code != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for malformed JSON, got %d", code)
		}
		if !strings.Contains(errOut, "failed to parse scan result") {
			t.Errorf("expected error explaining parse failure, got: %s", errOut)
		}
	})
}
