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

// Helper to create valid sample catalog JSON
func sampleCatalogJSON() string {
	return `{
  "schema_version": "1.0",
  "id": "nist-sp800-53-sample",
  "title": "NIST SP 800-53 Sample Benchmark",
  "version": "5.1.0",
  "framework": "NIST SP 800-53",
  "description": "Sample controls for automated compliance CLI verification",
  "source": {
    "name": "NIST SP 800-53 Rev. 5",
    "publisher": "National Institute of Standards and Technology",
    "is_authoritative": true,
    "license": "Public Domain"
  },
  "controls": [
    {
      "id": "AC-1",
      "title": "Access Control Policy and Procedures",
      "description": "Establish, document, and enforce access control policies and procedures.",
      "category": "access-control",
      "severity": "HIGH",
      "status": "active"
    },
    {
      "id": "AC-3",
      "title": "Access Enforcement",
      "description": "Enforce approved authorizations for logical access to information and system resources.",
      "category": "access-control",
      "severity": "CRITICAL",
      "status": "active"
    },
    {
      "id": "SC-8",
      "title": "Transmission Confidentiality and Integrity",
      "description": "Protect the confidentiality and integrity of transmitted information.",
      "category": "system-and-communications-protection",
      "severity": "HIGH",
      "status": "active"
    }
  ]
}`
}

// Helper to create valid sample mapping ruleset JSON
func sampleMappingRuleSetJSON() string {
	return `{
  "schema_version": "1.0",
  "id": "ruleset-nist-sample",
  "title": "FELIX Findings to NIST SP 800-53 Sample Mappings",
  "version": "1.0.0",
  "target_catalog_id": "nist-sp800-53-sample",
  "target_catalog_version": "5.1.0",
  "rules": [
    {
      "id": "MAP-BOLA-AC3",
      "source_rule_id": "rule-bola-01",
      "source_category": "broken-object-level-authorization",
      "target_control_id": "AC-3",
      "relationship": "direct",
      "rationale": "Object-level authorization bypass directly violates AC-3 access enforcement requirements.",
      "confidence": 1.0
    },
    {
      "id": "MAP-TLS-SC8",
      "source_rule_id": "rule-tls-01",
      "source_category": "cryptographic-failures",
      "target_control_id": "SC-8",
      "relationship": "direct",
      "rationale": "Insecure transmission protocols or plaintext communications violate SC-8 requirements.",
      "confidence": 1.0
    }
  ]
}`
}

func TestCLI_Compliance_HelpAndRouting(t *testing.T) {
	// 1. Root compliance without args displays help and exits 0
	codeRoot, outRoot, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance"})
	})
	if codeRoot != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for compliance without args, got %d", codeRoot)
	}
	if !strings.Contains(outRoot, "felix compliance <subcommand>") {
		t.Errorf("expected usage in help output, got: %s", outRoot)
	}

	// 2. Compliance --help exits 0
	codeHelp, outHelp, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "--help"})
	})
	if codeHelp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for compliance --help, got %d", codeHelp)
	}
	if !strings.Contains(outHelp, "catalog") || !strings.Contains(outHelp, "evaluate") {
		t.Errorf("expected subcommands listed in help, got: %s", outHelp)
	}

	// 3. Unknown subcommand returns ExitOperational (2)
	codeUnknown, _, errUnknown := captureStdoutStderr(func() int {
		return run([]string{"compliance", "unknown-subcommand"})
	})
	if codeUnknown != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for unknown subcommand, got %d", codeUnknown)
	}
	if !strings.Contains(errUnknown, "Unknown compliance command") {
		t.Errorf("expected error message on stderr, got: %s", errUnknown)
	}
}

func TestCLI_Compliance_Catalog_Workflows(t *testing.T) {
	tmpDir := t.TempDir()
	catPath := filepath.Join(tmpDir, "valid_catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	badCatPath := filepath.Join(tmpDir, "malformed_catalog.json")
	if err := os.WriteFile(badCatPath, []byte(`{ "id": "broken", invalid...`), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Validate valid catalog -> Exit 0
	codeVal, outVal, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "validate", catPath})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for catalog validate, got %d", codeVal)
	}
	if !strings.Contains(outVal, "VALID") || !strings.Contains(outVal, "Total Controls:     3") {
		t.Errorf("expected validation success output, got: %s", outVal)
	}
	if !strings.Contains(outVal, "Notice:") {
		t.Errorf("expected limitations notice in catalog validate output")
	}

	// 2. Validate valid catalog with --json -> clean JSON on stdout
	codeJSON, outJSON, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "validate", catPath, "--json"})
	})
	if codeJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeJSON)
	}
	var valMap map[string]any
	if err := json.Unmarshal([]byte(outJSON), &valMap); err != nil {
		t.Fatalf("expected clean JSON output from catalog validate --json, got error: %v, raw: %s", err, outJSON)
	}
	if valMap["valid"] != true || valMap["total_controls"] != float64(3) {
		t.Errorf("unexpected json validation values: %v", valMap)
	}

	// 3. Validate malformed catalog -> Exit 2
	codeBad, _, errBad := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "validate", badCatPath})
	})
	if codeBad != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for malformed catalog, got %d", codeBad)
	}
	if !strings.Contains(errBad, "validation failed") {
		t.Errorf("expected error message on stderr, got: %s", errBad)
	}

	// 4. Validate missing file argument -> Exit 2
	codeMissing, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "validate"})
	})
	if codeMissing != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing file arg, got %d", codeMissing)
	}

	// 5. Inspect catalog -> Exit 0
	codeInsp, outInsp, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "inspect", catPath})
	})
	if codeInsp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for catalog inspect, got %d", codeInsp)
	}
	if !strings.Contains(outInsp, "nist-sp800-53-sample:5.1.0") || !strings.Contains(outInsp, "Total Controls:     3") {
		t.Errorf("expected metadata in inspect output, got: %s", outInsp)
	}

	// 6. List controls in catalog -> Exit 0
	codeCtrl, outCtrl, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "controls", catPath})
	})
	if codeCtrl != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for catalog controls, got %d", codeCtrl)
	}
	if !strings.Contains(outCtrl, "AC-1") || !strings.Contains(outCtrl, "AC-3") || !strings.Contains(outCtrl, "SC-8") {
		t.Errorf("expected control IDs in output, got: %s", outCtrl)
	}

	// 7. Filter controls by category -> Exit 0
	codeFilt, outFilt, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "controls", catPath, "--category", "access-control"})
	})
	if codeFilt != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeFilt)
	}
	if !strings.Contains(outFilt, "AC-1") || !strings.Contains(outFilt, "AC-3") {
		t.Errorf("expected AC controls, got: %s", outFilt)
	}
	if strings.Contains(outFilt, "SC-8") {
		t.Errorf("did not expect SC-8 in category access-control filter, got: %s", outFilt)
	}
}

func TestCLI_Compliance_Mapping_Workflows(t *testing.T) {
	tmpDir := t.TempDir()
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	rsPath := filepath.Join(tmpDir, "mapping.json")
	if err := os.WriteFile(rsPath, []byte(sampleMappingRuleSetJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	findingsJSON := `[
  {
    "id": "F-BOLA-001",
    "rule_id": "rule-bola-01",
    "category": "broken-object-level-authorization",
    "title": "BOLA on user account API",
    "severity": "CRITICAL"
  },
  {
    "id": "F-TLS-001",
    "rule_id": "rule-tls-01",
    "category": "cryptographic-failures",
    "title": "Insecure TLS 1.0 supported",
    "severity": "HIGH"
  },
  {
    "id": "F-UNMAPPED-001",
    "rule_id": "rule-unknown-99",
    "category": "miscellaneous",
    "title": "Unknown exposure",
    "severity": "LOW"
  }
]`
	findingsPath := filepath.Join(tmpDir, "findings.json")
	if err := os.WriteFile(findingsPath, []byte(findingsJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Validate mapping ruleset without catalog -> Exit 0
	codeVal, outVal, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "validate", rsPath})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for mapping validate, got %d", codeVal)
	}
	if !strings.Contains(outVal, "VALID") || !strings.Contains(outVal, "Total Rules:            2") {
		t.Errorf("expected validation output, got: %s", outVal)
	}

	// 2. Validate mapping ruleset with --catalog compatibility -> Exit 0
	codeComp, outComp, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "validate", rsPath, "--catalog", catPath})
	})
	if codeComp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for mapping validate with catalog, got %d", codeComp)
	}
	if !strings.Contains(outComp, "Catalog Compatibility:  VERIFIED") {
		t.Errorf("expected catalog compatibility in output, got: %s", outComp)
	}

	// 3. Inspect mapping ruleset -> Exit 0
	codeInsp, outInsp, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "inspect", rsPath})
	})
	if codeInsp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for mapping inspect, got %d", codeInsp)
	}
	if !strings.Contains(outInsp, "ruleset-nist-sample:1.0.0") || !strings.Contains(outInsp, "Total Rules:            2") {
		t.Errorf("expected metadata in inspect output, got: %s", outInsp)
	}

	// 4. Map findings to controls -> Exit 0
	codeMap, outMap, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "map", rsPath, "--catalog", catPath, "--findings", findingsPath})
	})
	if codeMap != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for mapping map, got %d", codeMap)
	}
	if !strings.Contains(outMap, "Mapped Findings:        2") || !strings.Contains(outMap, "Unmapped Findings:      1") {
		t.Errorf("expected mapped and unmapped counts, got: %s", outMap)
	}
	if !strings.Contains(outMap, "F-BOLA-001") || !strings.Contains(outMap, "AC-3") {
		t.Errorf("expected BOLA to AC-3 mapping in table, got: %s", outMap)
	}
	if !strings.Contains(outMap, "F-UNMAPPED-001") {
		t.Errorf("expected unmapped finding in unmapped section, got: %s", outMap)
	}
	if !strings.Contains(outMap, "does NOT constitute a compliance evaluation") {
		t.Errorf("expected notice that mapping does not constitute compliance, got: %s", outMap)
	}

	// 5. Map findings with --json -> clean JSON on stdout
	codeMapJSON, outMapJSON, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "map", rsPath, "--catalog", catPath, "--findings", findingsPath, "--json"})
	})
	if codeMapJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeMapJSON)
	}
	var mRes compliance.MappingResult
	if err := json.Unmarshal([]byte(outMapJSON), &mRes); err != nil {
		t.Fatalf("expected clean JSON from mapping map --json, got: %v, raw: %s", err, outMapJSON)
	}
	if len(mRes.Mappings) != 2 || len(mRes.Unmapped) != 1 {
		t.Errorf("unexpected mapping result in JSON: %+v", mRes)
	}
}

func TestCLI_Compliance_Evaluate_Workflows(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_eval_test.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	rsPath := filepath.Join(tmpDir, "mapping.json")
	if err := os.WriteFile(rsPath, []byte(sampleMappingRuleSetJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	// Findings with non-compliance (BOLA violating AC-3)
	findingsViolationJSON := `[
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
	findingsViolationPath := filepath.Join(tmpDir, "findings_violation.json")
	if err := os.WriteFile(findingsViolationPath, []byte(findingsViolationJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Positive evidence satisfying controls AC-1, AC-3, SC-8
	posEvJSON := `[
  {
    "id": "PE-AC1",
    "control_id": "AC-1",
    "observation": "Access control policy v2.4 verified active and signed.",
    "method": "EXAMINE"
  },
  {
    "id": "PE-AC3",
    "control_id": "AC-3",
    "observation": "RBAC policy enforcement active on all endpoints.",
    "method": "TEST"
  },
  {
    "id": "PE-SC8",
    "control_id": "SC-8",
    "observation": "TLS 1.3 enforced on all communications.",
    "method": "TEST"
  }
]`
	posEvPath := filepath.Join(tmpDir, "positive_evidence.json")
	if err := os.WriteFile(posEvPath, []byte(posEvJSON), 0600); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(tmpDir, "compliance.key")
	if err := os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Evaluate with positive evidence and NO findings -> Compliant -> Exit 0
	codeCompliant, outCompliant, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "evaluate",
			"--catalog", catPath,
			"--assessment", "ASM-CLI-CLEAN",
			"--evidence", posEvPath,
			"--save",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeCompliant != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for clean evaluation, got %d, out: %s", codeCompliant, outCompliant)
	}
	if !strings.Contains(outCompliant, "[+] Compliant:             3") {
		t.Errorf("expected 3 compliant controls, got: %s", outCompliant)
	}
	if strings.Contains(outCompliant, "[-] Non-Compliant:         0") == false {
		t.Errorf("expected 0 non-compliant controls, got: %s", outCompliant)
	}

	// 2. Evaluate with findings mapped to AC-3 -> Non-compliant -> Exit 1
	codeViolation, outViolation, errViolation := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "evaluate",
			"--catalog", catPath,
			"--assessment", "ASM-CLI-VIOLATION",
			"--mapping", rsPath,
			"--findings", findingsViolationPath,
			"--evidence", posEvPath,
			"--save",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeViolation != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for compliance violation, got %d, out: %s, err: %s", codeViolation, outViolation, errViolation)
	}
	if !strings.Contains(outViolation, "[-] Non-Compliant:         1") {
		t.Errorf("expected 1 non-compliant control, got: %s", outViolation)
	}

	// 3. Evaluate with missing required arguments -> Exit 2
	codeMissingCat, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluate", "--assessment", "ASM-01"})
	})
	if codeMissingCat != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing catalog, got %d", codeMissingCat)
	}

	codeMissingAss, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluate", "--catalog", catPath})
	})
	if codeMissingAss != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing assessment, got %d", codeMissingAss)
	}

	// 4. Evaluate with failed assessment status -> Exit 2
	codeFailedStatus, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "evaluate",
			"--catalog", catPath,
			"--assessment", "ASM-CLI-FAILED-STATUS",
			"--status", "FAILED",
		})
	})
	if codeFailedStatus != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for incomplete assessment status, got %d", codeFailedStatus)
	}
}

func TestCLI_Compliance_Evaluation_PersistenceAndInspection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_eval_inspect.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	rsPath := filepath.Join(tmpDir, "mapping.json")
	if err := os.WriteFile(rsPath, []byte(sampleMappingRuleSetJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	posEvJSON := `[
  {
    "id": "PE-AC1",
    "control_id": "AC-1",
    "observation": "Access control policy v2.4 active.",
    "method": "EXAMINE"
  }
]`
	posEvPath := filepath.Join(tmpDir, "pos_ev.json")
	if err := os.WriteFile(posEvPath, []byte(posEvJSON), 0600); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(tmpDir, "compliance.key")
	if err := os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600); err != nil {
		t.Fatal(err)
	}

	// Run evaluation and save
	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-INSPECT-01",
		"--evidence", posEvPath,
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})

	// 1. Evaluation list -> Exit 0
	codeList, outList, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "list", "--db", dbPath})
	})
	if codeList != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for evaluation list, got %d", codeList)
	}
	if !strings.Contains(outList, "ASM-INSPECT-01") {
		t.Errorf("expected ASM-INSPECT-01 in evaluation list, got: %s", outList)
	}

	// 2. Evaluation list --json -> clean JSON
	codeListJSON, outListJSON, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "list", "--db", dbPath, "--json"})
	})
	if codeListJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeListJSON)
	}
	var listSummaries []compliance.EvaluationResultSummary
	if err := json.Unmarshal([]byte(outListJSON), &listSummaries); err != nil {
		t.Fatalf("expected clean JSON from evaluation list, got error: %v, raw: %s", err, outListJSON)
	}
	if len(listSummaries) != 1 || listSummaries[0].AssessmentID != "ASM-INSPECT-01" {
		t.Errorf("unexpected list summaries: %+v", listSummaries)
	}

	// 3. Evaluation view <id> with --key-file -> reports integrity status
	codeView, outView, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "view", "ASM-INSPECT-01", "--db", dbPath, "--key-file", keyPath})
	})
	if codeView != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for evaluation view without violations, got %d", codeView)
	}
	if !strings.Contains(outView, "=== FELIX Evaluation Record ===") || !strings.Contains(outView, "ASM-INSPECT-01") {
		t.Errorf("expected evaluation view details, got: %s", outView)
	}
	if !strings.Contains(outView, "Integrity Verification: VERIFIED") {
		t.Errorf("expected integrity verified in view output, got: %s", outView)
	}

	// 4. Evaluation view for nonexistent ID -> Exit 2
	codeNonexistent, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "view", "ASM-NONEXISTENT", "--db", dbPath})
	})
	if codeNonexistent != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for nonexistent assessment, got %d", codeNonexistent)
	}

	// 5. Evaluation controls -> Exit 0
	codeCtrls, outCtrls, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "controls", "--assessment", "ASM-INSPECT-01", "--db", dbPath})
	})
	if codeCtrls != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for evaluation controls, got %d", codeCtrls)
	}
	if !strings.Contains(outCtrls, "AC-1") {
		t.Errorf("expected AC-1 in control list, got: %s", outCtrls)
	}

	// 6. Evaluation controls with --state filter -> Exit 0
	codeStateFilt, outStateFilt, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "controls", "--assessment", "ASM-INSPECT-01", "--state", "compliant", "--db", dbPath})
	})
	if codeStateFilt != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for state filter, got %d", codeStateFilt)
	}
	if !strings.Contains(outStateFilt, "AC-1") {
		t.Errorf("expected AC-1 in compliant controls filter, got: %s", outStateFilt)
	}

	// 7. Evaluation controls with invalid state -> Exit 2
	codeBadState, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "controls", "--state", "invalid-state", "--db", dbPath})
	})
	if codeBadState != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for invalid evaluation state, got %d", codeBadState)
	}

	// 8. Evaluation evidence -> Exit 0
	evalID := "eval:ASM-INSPECT-01:nist-sp800-53-sample:AC-1"
	codeEv, outEv, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "evidence", evalID, "--db", dbPath})
	})
	if codeEv != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for evaluation evidence, got %d", codeEv)
	}
	if !strings.Contains(outEv, "PE-AC1") {
		t.Errorf("expected PE-AC1 in evidence output, got: %s", outEv)
	}
}

func TestCLI_Compliance_Verify_Workflows(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_verify.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmpDir, "compliance.key")
	if err := os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600); err != nil {
		t.Fatal(err)
	}

	// Create and save signed evaluation
	_ = run([]string{
		"compliance", "evaluate",
		"--catalog", catPath,
		"--assessment", "ASM-VERIFY-01",
		"--save",
		"--db", dbPath,
		"--key-file", keyPath,
	})

	// 1. Verify with valid key -> Exit 0
	codeVer, outVer, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "verify",
			"--assessment", "ASM-VERIFY-01",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeVer != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for verified evaluation, got %d, out: %s", codeVer, outVer)
	}
	if !strings.Contains(outVer, "VERIFIED") || !strings.Contains(outVer, "SUCCESS") {
		t.Errorf("expected SUCCESS in verification output, got: %s", outVer)
	}

	// 2. Verify with --json output -> clean JSON
	codeVerJSON, outVerJSON, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "verify",
			"--assessment", "ASM-VERIFY-01",
			"--db", dbPath,
			"--key-file", keyPath,
			"--json",
		})
	})
	if codeVerJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", codeVerJSON)
	}
	var verResult compliance.IntegrityVerificationResult
	if err := json.Unmarshal([]byte(outVerJSON), &verResult); err != nil {
		t.Fatalf("expected clean JSON from verify --json, got: %v, raw: %s", err, outVerJSON)
	}
	if verResult.Status != compliance.StatusVerified || !verResult.AuthenticityMatch {
		t.Errorf("unexpected verification result: %+v", verResult)
	}

	// 3. Verify on tampered record -> Exit 1 (ExitSecurityFail)
	// Mutate evaluation directly in SQLite to simulate database-level tampering
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec("UPDATE compliance_control_evaluations SET state = 'compliant', rationale = 'Tampered' WHERE assessment_id = 'ASM-VERIFY-01'"); err != nil {
		rawDB.Close()
		t.Fatal(err)
	}
	rawDB.Close()

	codeTampered, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "verify",
			"--assessment", "ASM-VERIFY-01",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if codeTampered != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for tampered record, got %d", codeTampered)
	}

	// 4. Verify with missing flags -> Exit 2
	codeMissingFlags, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "verify"})
	})
	if codeMissingFlags != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing flags, got %d", codeMissingFlags)
	}
}

func TestCLI_Compliance_EndToEnd_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_full_lifecycle.db")
	catPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catPath, []byte(sampleCatalogJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	rsPath := filepath.Join(tmpDir, "mapping.json")
	if err := os.WriteFile(rsPath, []byte(sampleMappingRuleSetJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	findingsJSON := `[
  {
    "id": "F-BOLA-E2E",
    "rule_id": "rule-bola-01",
    "category": "broken-object-level-authorization",
    "title": "BOLA critical failure",
    "severity": "CRITICAL",
    "status": "CONFIRMED",
    "confidence": "HIGH",
    "evidence_summary": "Exploitable BOLA in user endpoint verified with payload"
  }
]`
	findingsPath := filepath.Join(tmpDir, "findings.json")
	if err := os.WriteFile(findingsPath, []byte(findingsJSON), 0600); err != nil {
		t.Fatal(err)
	}
	posEvJSON := `[
  {
    "id": "PE-AC1",
    "control_id": "AC-1",
    "observation": "Access control policy v2.4 active.",
    "method": "EXAMINE"
  }
]`
	posEvPath := filepath.Join(tmpDir, "pos_ev.json")
	if err := os.WriteFile(posEvPath, []byte(posEvJSON), 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmpDir, "compliance.key")
	if err := os.WriteFile(keyPath, []byte("dGVzdC1obWFjLXNpZ25pbmcta2V5LWZvci1ldmFsdWF0aW9uCg=="), 0600); err != nil {
		t.Fatal(err)
	}

	// Step 1: Catalog validate
	code1, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "catalog", "validate", catPath})
	})
	if code1 != clierror.ExitSuccess {
		t.Fatalf("Step 1 failed with exit code %d", code1)
	}

	// Step 2: Mapping validate against catalog
	code2, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "validate", rsPath, "--catalog", catPath})
	})
	if code2 != clierror.ExitSuccess {
		t.Fatalf("Step 2 failed with exit code %d", code2)
	}

	// Step 3: Mapping map findings
	code3, out3, err3 := captureStdoutStderr(func() int {
		return run([]string{"compliance", "mapping", "map", rsPath, "--catalog", catPath, "--findings", findingsPath})
	})
	if code3 != clierror.ExitSuccess {
		t.Fatalf("Step 3 failed with exit code %d, out: %s, err: %s", code3, out3, err3)
	}

	// Step 4: Evaluate and persist with HMAC key
	code4, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "evaluate",
			"--catalog", catPath,
			"--assessment", "ASM-E2E-01",
			"--mapping", rsPath,
			"--findings", findingsPath,
			"--evidence", posEvPath,
			"--save",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	// AC-3 is non-compliant, so evaluation returns ExitSecurityFail (1)
	if code4 != clierror.ExitSecurityFail {
		t.Fatalf("Step 4 expected ExitSecurityFail (1), got %d", code4)
	}

	// Step 5: List evaluations
	code5, out5, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "list", "--db", dbPath})
	})
	if code5 != clierror.ExitSuccess || !strings.Contains(out5, "ASM-E2E-01") {
		t.Fatalf("Step 5 failed: code=%d, out=%s", code5, out5)
	}

	// Step 6: View evaluation
	code6, out6, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "evaluation", "view", "ASM-E2E-01", "--db", dbPath, "--key-file", keyPath})
	})
	// Evaluation contains non-compliant AC-3, so returns ExitSecurityFail (1)
	if code6 != clierror.ExitSecurityFail || !strings.Contains(out6, "ASM-E2E-01") {
		t.Fatalf("Step 6 failed: code=%d, out=%s", code6, out6)
	}

	// Step 7: Verify integrity
	code7, out7, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "verify", "--assessment", "ASM-E2E-01", "--db", dbPath, "--key-file", keyPath})
	})
	if code7 != clierror.ExitSuccess || !strings.Contains(out7, "VERIFIED") {
		t.Fatalf("Step 7 failed: code=%d, out=%s", code7, out7)
	}

	// Step 8: Assign remediation SLA
	code8, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "sla", "assign",
			"--id", "rem:e2e:1",
			"--finding", "F-BOLA-E2E",
			"--assessment", "ASM-E2E-01",
			"--catalog", "nist-sp800-53-sample:5.1.0",
			"--control", "AC-3",
			"--severity", "CRITICAL",
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	if code8 != clierror.ExitSuccess {
		t.Fatalf("Step 8 failed with exit code %d", code8)
	}

	// Step 9: Generate Dossier
	dossierFile := filepath.Join(tmpDir, "dossier.json")
	code9, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-E2E-01",
			"--catalog", "nist-sp800-53-sample:5.1.0",
			"--catalog-file", catPath,
			"--output", dossierFile,
			"--db", dbPath,
			"--key-file", keyPath,
		})
	})
	// Dossier contains non-compliant controls, so generate returns ExitSecurityFail (1)
	if code9 != clierror.ExitSecurityFail {
		t.Fatalf("Step 9 failed with exit code %d (expected ExitSecurityFail 1)", code9)
	}

	// Step 10: Validate Dossier
	code10, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "validate", dossierFile})
	})
	if code10 != clierror.ExitSuccess {
		t.Fatalf("Step 10 failed with exit code %d", code10)
	}

	// Step 11: Export to Normalized JSON and Validate
	normExportFile := filepath.Join(tmpDir, "export_norm.json")
	code11, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--dossier-file", dossierFile,
			"--output", normExportFile,
		})
	})
	// Export contains non-compliant controls, so returns ExitSecurityFail (1)
	if code11 != clierror.ExitSecurityFail {
		t.Fatalf("Step 11 failed with exit code %d (expected ExitSecurityFail 1)", code11)
	}

	code11Val, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", normExportFile})
	})
	if code11Val != clierror.ExitSuccess {
		t.Fatalf("Step 11 validate failed with exit code %d", code11Val)
	}

	// Step 12: Export to OSCAL Assessment Results and Validate against official schema
	oscalExportFile := filepath.Join(tmpDir, "export_oscal_ar.json")
	code12, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "oscal",
			"--dossier-file", dossierFile,
			"--output", oscalExportFile,
		})
	})
	// Export contains non-compliant controls, so returns ExitSecurityFail (1)
	if code12 != clierror.ExitSecurityFail {
		t.Fatalf("Step 12 failed with exit code %d (expected ExitSecurityFail 1)", code12)
	}

	code12Val, out12Val, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", oscalExportFile})
	})
	if code12Val != clierror.ExitSuccess {
		t.Fatalf("Step 12 validate failed with exit code %d, out: %s", code12Val, out12Val)
	}
}
