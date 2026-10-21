package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func TestCLI_Compliance_Gate_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "--help"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for gate help, got %d", code)
	}
	for _, expected := range []string{
		"felix compliance gate",
		"validate",
		"inspect",
		"check",
		"--policy",
		"--assessment",
		"Exit Codes:",
		"0  PASS",
		"1  POLICY FAILURE",
		"2  OPERATIONAL FAILURE",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %q in gate help output", expected)
		}
	}
}

func TestCLI_Compliance_Gate_Validate_And_Inspect(t *testing.T) {
	tmpDir := t.TempDir()

	validPolicyJSON := `{
  "schema_version": "1.0",
  "id": "gate-policy-prod",
  "name": "Production Gate Policy",
  "version": "1.0.0",
  "target_catalog": "nist-sp800-53-sample",
  "enforced_controls": ["AC-1", "AC-3"],
  "min_compliance_percent": 100.0,
  "max_non_compliant": 0,
  "require_integrity": true
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(validPolicyJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Validate valid policy -> Exit 0
	codeVal, outVal, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "validate", policyPath})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for gate validate, got %d", codeVal)
	}
	if !strings.Contains(outVal, "gate-policy-prod") || !strings.Contains(outVal, "VALID") {
		t.Errorf("expected success message in validate output, got: %s", outVal)
	}

	// 2. Validate valid policy with --json -> clean JSON
	codeValJSON, outValJSON, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "validate", policyPath, "--json"})
	})
	if codeValJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeValJSON)
	}
	var valResp map[string]any
	if err := json.Unmarshal([]byte(outValJSON), &valResp); err != nil {
		t.Fatalf("expected clean JSON from gate validate --json, got: %v", err)
	}
	if valResp["valid"] != true {
		t.Errorf("expected valid=true in JSON response, got: %v", valResp)
	}

	// 3. Inspect valid policy -> Exit 0
	codeInsp, outInsp, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "inspect", policyPath})
	})
	if codeInsp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for gate inspect, got %d", codeInsp)
	}
	if !strings.Contains(outInsp, "gate-policy-prod") || !strings.Contains(outInsp, "Enforced Controls (2)") {
		t.Errorf("expected inspection details, got: %s", outInsp)
	}

	// 4. Validate malformed policy -> Exit 2
	badPolicyPath := filepath.Join(tmpDir, "bad_policy.json")
	_ = os.WriteFile(badPolicyPath, []byte(`{"schema_version": "99.0", "id": "bad"}`), 0600)
	codeBad, _, errBad := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "validate", badPolicyPath})
	})
	if codeBad != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for malformed policy, got %d", codeBad)
	}
	if !strings.Contains(errBad, "unsupported schema_version") {
		t.Errorf("expected version error on stderr, got: %s", errBad)
	}
}

func TestCLI_Compliance_Gate_Check_PassingEvaluation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_gate_pass.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	posEvJSON := `[
  {
    "id": "PE-AC1",
    "control_id": "AC-1",
    "observation": "Access control policy verified.",
    "method": "EXAMINE"
  },
  {
    "id": "PE-AC3",
    "control_id": "AC-3",
    "observation": "Access enforcement verified.",
    "method": "TEST"
  },
  {
    "id": "PE-SC8",
    "control_id": "SC-8",
    "observation": "Transmission confidentiality verified.",
    "method": "TEST"
  }
]`
	posEvPath := filepath.Join(tmpDir, "positive_ev.json")
	_ = os.WriteFile(posEvPath, []byte(posEvJSON), 0600)

	keyPath := filepath.Join(tmpDir, "compliance.key")
	_ = os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600)

	// Persist passing evaluation
	codeEval := run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-GATE-PASS",
		"--evidence", posEvPath,
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})
	if codeEval != clierror.ExitSuccess {
		t.Fatalf("setup evaluate failed with code %d", codeEval)
	}

	// Policy requiring 100% compliance
	policyJSON := `{
  "schema_version": "1.0",
  "id": "policy-pass-test",
  "version": "1.0.0",
  "target_catalog": "nist-sp800-53-sample",
  "enforced_controls": ["AC-1", "AC-3", "SC-8"],
  "min_compliance_percent": 100.0,
  "max_non_compliant": 0,
  "require_integrity": true
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policyJSON), 0600)

	// 1. Run gate check -> Exit 0
	codeGate, outGate, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-GATE-PASS",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeGate != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for passing gate, got %d, out: %s", codeGate, outGate)
	}
	if !strings.Contains(outGate, "DECISION:  [+] PASSED") {
		t.Errorf("expected PASSED decision in report, got: %s", outGate)
	}

	// 2. Run gate check with --json -> Valid JSON on stdout
	codeGateJSON, outGateJSON, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate",
			"--policy", policyPath,
			"--assessment", "ASM-GATE-PASS",
			"--db", dbPath,
			"--key-file", keyPath,
			"--json",
		})
	})
	if codeGateJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for gate --json, got %d", codeGateJSON)
	}
	var gateRes compliance.ComplianceGateResult
	if err := json.Unmarshal([]byte(outGateJSON), &gateRes); err != nil {
		t.Fatalf("expected clean JSON from gate check, got error: %v, raw: %s", err, outGateJSON)
	}
	if gateRes.Decision != compliance.GateStatusPassed || gateRes.ExitCode != 0 {
		t.Errorf("unexpected gate result in JSON: %+v", gateRes)
	}
}

func TestCLI_Compliance_Gate_Check_PolicyFailure(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_gate_fail.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	_ = os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600)
	rsPath := filepath.Join(tmpDir, "mapping.json")
	_ = os.WriteFile(rsPath, []byte(sampleMappingRuleSetJSON()), 0600)

	findingsJSON := `[
  {
    "id": "F-BOLA-001",
    "rule_id": "rule-bola-01",
    "category": "broken-object-level-authorization",
    "title": "BOLA unauthorized access",
    "severity": "CRITICAL",
    "status": "CONFIRMED",
    "confidence": "HIGH",
    "evidence_summary": "Unauthorized access to object ID 1042 allowed without authorization token"
  }
]`
	findingsPath := filepath.Join(tmpDir, "findings.json")
	_ = os.WriteFile(findingsPath, []byte(findingsJSON), 0600)

	posEvJSON := `[
  {
    "id": "PE-AC1",
    "control_id": "AC-1",
    "observation": "Access control policy verified.",
    "method": "EXAMINE"
  }
]`
	posEvPath := filepath.Join(tmpDir, "pos_ev.json")
	_ = os.WriteFile(posEvPath, []byte(posEvJSON), 0600)

	keyPath := filepath.Join(tmpDir, "compliance.key")
	_ = os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600)

	// Persist non-compliant evaluation (AC-3 violated by BOLA)
	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-GATE-FAIL",
		"--mapping", rsPath,
		"--findings", findingsPath,
		"--evidence", posEvPath,
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})

	// Policy enforcing AC-3 compliance
	policyJSON := `{
  "schema_version": "1.0",
  "id": "policy-fail-test",
  "version": "1.0.0",
  "target_catalog": "nist-sp800-53-sample",
  "enforced_controls": ["AC-3"],
  "max_non_compliant": 0
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policyJSON), 0600)

	// Gate check -> Exit 1 (ExitSecurityFail)
	codeGate, outGate, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-GATE-FAIL",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeGate != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for policy failure, got %d, out: %s", codeGate, outGate)
	}
	if !strings.Contains(outGate, "DECISION:  [-] POLICY_FAILED") {
		t.Errorf("expected POLICY_FAILED in gate report, got: %s", outGate)
	}
	if !strings.Contains(outGate, "enforced control AC-3 is non-compliant") {
		t.Errorf("expected AC-3 non-compliant failure reason in report, got: %s", outGate)
	}
}

func TestCLI_Compliance_Gate_Check_OperationalFailure(t *testing.T) {
	tmpDir := t.TempDir()
	policyJSON := `{
  "schema_version": "1.0",
  "id": "policy-op-test",
  "version": "1.0.0"
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policyJSON), 0600)

	// 1. Nonexistent assessment -> Exit 2
	codeNonexistent, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-DOES-NOT-EXIST",
			"--db", filepath.Join(tmpDir, "nonexistent.db"),
		})
	})
	if codeNonexistent != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for nonexistent assessment, got %d", codeNonexistent)
	}

	// 2. Missing policy argument -> Exit 2
	codeMissingPol, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "gate", "check", "--assessment", "ASM-01"})
	})
	if codeMissingPol != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing policy, got %d", codeMissingPol)
	}

	// 3. Incomplete assessment status override -> Exit 2
	catPath := filepath.Join(tmpDir, "catalog.json")
	_ = os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600)
	dbPath := filepath.Join(tmpDir, "op_test.db")
	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-OP-STATUS",
		"--save",
		"--db", dbPath,
	})

	codeIncomplete, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-OP-STATUS",
			"--status", "FAILED",
			"--db", dbPath,
		})
	})
	if codeIncomplete != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for incomplete status override, got %d", codeIncomplete)
	}
}

func TestCLI_Compliance_Gate_ReportArtifact_And_Tampering(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_gate_tamper.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	_ = os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600)
	keyPath := filepath.Join(tmpDir, "compliance.key")
	_ = os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600)

	posEvJSON := `[{"id": "PE-AC1", "control_id": "AC-1", "observation": "ok", "method": "TEST"}]`
	posEvPath := filepath.Join(tmpDir, "pe.json")
	_ = os.WriteFile(posEvPath, []byte(posEvJSON), 0600)

	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-TAMPER-GATE",
		"--evidence", posEvPath,
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})

	policyJSON := `{
  "schema_version": "1.0",
  "id": "policy-tamper",
  "version": "1.0.0",
  "strict_integrity": true
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policyJSON), 0600)

	// 1. Report writing to --output
	reportPath := filepath.Join(tmpDir, "gate_report.json")
	codeRep, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-TAMPER-GATE",
			"--db", dbPath,
			"--key-file", keyPath,
			"--output", reportPath,
		})
	})
	// Policy has unassessed controls (AC-3, SC-8) with default fail_closed -> Exit 1
	if codeRep != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1), got %d", codeRep)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected gate report artifact to be created at %s", reportPath)
	}

	// Overwrite guard: running again without --overwrite should fail overwrite check
	codeNoOverwrite, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-TAMPER-GATE",
			"--db", dbPath,
			"--key-file", keyPath,
			"--output", reportPath,
		})
	})
	if codeNoOverwrite != clierror.ExitSecurityFail {
		// Preserves primary policy violation exit code 1!
		t.Errorf("expected ExitSecurityFail (1) preserving primary policy violation, got %d", codeNoOverwrite)
	}

	// 2. Tamper evaluation directly in database to test strict integrity
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDB.Exec("UPDATE compliance_control_evaluations SET state = 'compliant', rationale = 'Tampered' WHERE assessment_id = 'ASM-TAMPER-GATE'")
	if err != nil {
		t.Fatal(err)
	}
	rawDB.Close()

	// Under strict integrity, tampered record MUST result in ExitOperational (2)
	codeTampered, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--assessment", "ASM-TAMPER-GATE",
			"--db", dbPath,
			"--key-file", keyPath,
			"--strict-integrity",
		})
	})
	if codeTampered != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for tampered record under strict integrity, got %d", codeTampered)
	}
}

func TestCLI_Compliance_Gate_DossierFileEvaluation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_dossier_gate.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	_ = os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600)
	keyPath := filepath.Join(tmpDir, "compliance.key")
	_ = os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600)

	posEvJSON := `[
  {"id": "PE-AC1", "control_id": "AC-1", "observation": "ok", "method": "TEST"},
  {"id": "PE-AC3", "control_id": "AC-3", "observation": "ok", "method": "TEST"},
  {"id": "PE-SC8", "control_id": "SC-8", "observation": "ok", "method": "TEST"}
]`
	posEvPath := filepath.Join(tmpDir, "pe.json")
	_ = os.WriteFile(posEvPath, []byte(posEvJSON), 0600)

	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-DOSSIER-CLI",
		"--evidence", posEvPath,
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})

	dossierFile := filepath.Join(tmpDir, "dossier.json")
	codeGen := run([]string{
		"compliance", "dossier", "generate",
		"--assessment", "ASM-DOSSIER-CLI",
		"--catalog", "nist-sp800-53-sample:5.1.0",
		"--catalog-file", catPath,
		"--output", dossierFile,
		"--db", dbPath,
		"--key-file", keyPath,
	})
	if codeGen != clierror.ExitSuccess {
		t.Fatalf("setup dossier generate failed with code %d", codeGen)
	}

	policyJSON := `{
  "schema_version": "1.0",
  "id": "policy-dossier-cli",
  "version": "1.0.0",
  "enforced_controls": ["AC-1", "AC-3"]
}`
	policyPath := filepath.Join(tmpDir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policyJSON), 0600)

	codeDossier, outDossier, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "gate", "check",
			"--policy", policyPath,
			"--dossier-file", dossierFile,
		})
	})
	if codeDossier != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for dossier gate check, got %d, out: %s", codeDossier, outDossier)
	}
	if !strings.Contains(outDossier, "DECISION:  [+] PASSED") {
		t.Errorf("expected PASSED decision, got: %s", outDossier)
	}
}
