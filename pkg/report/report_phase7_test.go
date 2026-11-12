package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase7_NormalizeVerificationStatusAndSummarySync(t *testing.T) {
	if got := NormalizeVerificationStatus("CONFIRMED"); got != VerificationVerified {
		t.Fatalf("expected CONFIRMED -> %s, got %s", VerificationVerified, got)
	}
	if got := NormalizeVerificationStatus("POTENTIAL"); got != VerificationDetected {
		t.Fatalf("expected POTENTIAL -> %s, got %s", VerificationDetected, got)
	}
	if got := NormalizeVerificationStatus("NOT VALIDATED"); got != VerificationNotVerified {
		t.Fatalf("expected NOT VALIDATED -> %s, got %s", VerificationNotVerified, got)
	}
	if got := NormalizeVerificationStatus("FIX DETECTED"); got != VerificationNotExposed {
		t.Fatalf("expected FIX DETECTED -> %s, got %s", VerificationNotExposed, got)
	}

	now := time.Now().UTC()
	rep := Report{
		Target:           "http://127.0.0.1:5000",
		CompletionStatus: "COMPLETED",
		Timestamp:        now.Format(time.RFC3339),
		Findings: []Finding{
			{
				ID:       "F-SQLI-1",
				Title:    "SQL Injection in /users",
				Category: "SQL Injection",
				Severity: "CRITICAL",
				Target:   "http://127.0.0.1:5000",
				Endpoint: "/users?id=1",
				Method:   "GET",
				Verification: VerificationRecord{
					Status: VerificationStatus("CONFIRMED"),
				},
			},
			{
				ID:       "F-BOLA-1",
				Title:    "Broken Object Level Authorization",
				Category: "BOLA",
				Severity: "HIGH",
				Target:   "http://127.0.0.1:5000",
				Endpoint: "/books/v1/book1",
				Method:   "GET",
				Verification: VerificationRecord{
					Status: VerificationVerified,
				},
			},
			{
				ID:       "F-HDR-1",
				Title:    "Missing Content-Security-Policy (CSP)",
				Category: "Missing Security Header",
				Severity: "MEDIUM",
				Target:   "http://127.0.0.1:5000",
				Endpoint: "/",
				Method:   "GET",
				Verification: VerificationRecord{
					Status: VerificationDetected,
				},
			},
		},
		// Deliberately stale summary before RecalculateReportRisk
		Summary: Summary{
			TotalFindings: 1,
			HighCount:     1,
		},
	}

	RecalculateReportRisk(&rep)

	if rep.Summary.TotalFindings != len(rep.Findings) {
		t.Fatalf("expected Summary.TotalFindings=%d, got %d", len(rep.Findings), rep.Summary.TotalFindings)
	}
	if rep.Summary.CriticalCount != 1 || rep.Summary.HighCount != 1 || rep.Summary.MediumCount != 1 {
		t.Fatalf("unexpected severity counts: %+v", rep.Summary)
	}
	if rep.CommercialReport == nil {
		t.Fatalf("expected CommercialReport to be populated")
	}
	if rep.CommercialReport.ExecutiveSummary.FindingsVerifiedCount != 2 {
		t.Fatalf("expected FindingsVerifiedCount=2 (CONFIRMED + VERIFIED), got %d", rep.CommercialReport.ExecutiveSummary.FindingsVerifiedCount)
	}

	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := WriteHTML(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("ReadFile HTML failed: %v", err)
	}
	htmlStr := string(htmlBytes)
	if strings.Contains(htmlStr, "No security findings were discovered") {
		t.Fatalf("HTML report falsely claimed zero security findings despite 3 findings")
	}
	if !strings.Contains(htmlStr, "SQL Injection in /users") {
		t.Fatalf("HTML report missing finding title")
	}

	sarifPath := filepath.Join(tmpDir, "report.sarif")
	if err := WriteSARIF(rep, sarifPath); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	sarifBytes, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("ReadFile SARIF failed: %v", err)
	}
	var sarifDoc struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(sarifDoc.Runs) == 0 || len(sarifDoc.Runs[0].Results) != len(rep.Findings) {
		t.Fatalf("expected %d SARIF results matching findings count, got %d", len(rep.Findings), len(sarifDoc.Runs[0].Results))
	}
}
