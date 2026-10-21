package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func TestCLI_Compliance_Limitations_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "--help"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for limitations help, got %d", code)
	}
	for _, expected := range []string{
		"felix compliance limitations",
		"inspect",
		"list",
		"check",
		"boundaries",
		"--assessment",
		"--dossier-file",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %q in limitations help output", expected)
		}
	}
}

func TestCLI_Compliance_Limitations_Boundaries(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "boundaries"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for boundaries, got %d", code)
	}
	for _, expected := range []string{
		"=== FELIX Compliance Determination Boundaries ===",
		"1. Technical Evidence:",
		"2. Control Mapping:",
		"3. Control Evaluation:",
		"4. Assessment Coverage:",
		"5. Policy & Gate Decisions:",
		"6. Statutory Disclaimer:",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %q in boundaries output", expected)
		}
	}
}

func TestCLI_Compliance_Limitations_Inspect_And_List(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_test.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	evalTime := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	eval := &compliance.EvaluationResult{
		AssessmentID:    "ASM-CLI-LIM",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EvaluatedAt:     evalTime,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:1",
				CatalogID:          "nist-sp800-53-sample",
				ControlID:          "AC-1",
				State:              compliance.StateCompliant,
				Rationale:          "Policy active",
				SupportingEvidence: []string{"PE-1"},
				EvaluatedAt:        evalTime,
			},
			{
				EvaluationID: "eval:2",
				CatalogID:    "nist-sp800-53-sample",
				ControlID:    "AC-2",
				State:        compliance.StateNotAssessed,
				Rationale:    "Control was not assessed",
				EvaluatedAt:  evalTime,
			},
		},
		Summary: compliance.EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     1,
			NotAssessedCount:   1,
			ApplicableControls: 2,
			AssessedControls:   1,
		},
	}
	if err := store.SaveEvaluationResult(eval); err != nil {
		t.Fatal(err)
	}
	store.Close()

	// 1. Test inspect subcommand
	codeInspect, outInspect, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "inspect", "--assessment", "ASM-CLI-LIM", "--db", dbPath})
	})
	if codeInspect != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for inspect, got %d", codeInspect)
	}
	for _, expected := range []string{
		"=== FELIX Compliance Limitations & Determination Boundaries ===",
		"Target Assessment:          ASM-CLI-LIM",
		"Assessment Coverage Basis:",
		"Total Catalog Controls:   2",
		"Assessed Controls:        1 (50.0% evaluated coverage)",
		"Unassessed Controls:      1 (Must NOT be assumed compliant)",
		"Limitation & Evidence Boundaries",
		"LIM-COV-UNASSESSED",
		"LIM-CERT-DISCLAIMER",
	} {
		if !strings.Contains(outInspect, expected) {
			t.Errorf("expected %q in inspect output", expected)
		}
	}

	// 2. Test list subcommand
	codeList, outList, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "list", "--assessment", "ASM-CLI-LIM", "--db", dbPath})
	})
	if codeList != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for list, got %d", codeList)
	}
	if !strings.Contains(outList, "LIM-COV-UNASSESSED") || !strings.Contains(outList, "LIM-CERT-DISCLAIMER") {
		t.Errorf("expected limitation IDs in list output: %s", outList)
	}

	// 3. Test check subcommand on valid evaluation
	codeCheck, outCheck, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "check", "--assessment", "ASM-CLI-LIM", "--db", dbPath})
	})
	if codeCheck != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for check, got %d", codeCheck)
	}
	if !strings.Contains(outCheck, "CONSISTENT and VALID") {
		t.Errorf("expected consistency confirmation in check output: %s", outCheck)
	}

	// 4. Test --json flag on inspect
	codeJSON, outJSON, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "limitations", "inspect", "--assessment", "ASM-CLI-LIM", "--db", dbPath, "--json"})
	})
	if codeJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for JSON inspect, got %d", codeJSON)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(outJSON), &parsed); err != nil {
		t.Fatalf("failed parsing JSON inspect output: %v\nOutput: %s", err, outJSON)
	}
	if parsed["coverage_basis"] == nil || parsed["limitations"] == nil {
		t.Errorf("expected coverage_basis and limitations in JSON output")
	}
}
