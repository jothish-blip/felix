package test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase94_CompliancePersistence_EndToEnd tests the complete Phase 9.4 compliance persistence pipeline:
// evaluation generation, atomic durable storage, multi-dimensional query and filtering,
// structured evidence retrieval, restart/reopen persistence, idempotent retries, and conflict rejection.
func TestPhase94_CompliancePersistence_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Setup Validated Catalog
	catalogJSON := `{
		"schema_version": "1.0",
		"id": "nist-sp800-53-persist-e2e",
		"title": "NIST SP 800-53 Persistence Test Catalog",
		"version": "5.1.0",
		"framework": "NIST",
		"controls": [
			{
				"id": "AC-3",
				"title": "Access Enforcement",
				"description": "Enforce approved authorizations for logical access.",
				"status": "active"
			},
			{
				"id": "SI-10",
				"title": "Information Input Validation",
				"description": "Check information inputs for validity.",
				"status": "active"
			},
			{
				"id": "SC-13",
				"title": "Cryptographic Protection",
				"description": "Implement cryptographic mechanisms to protect data in transit.",
				"status": "active"
			}
		]
	}`

	catalogPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(catalogJSON), 0644); err != nil {
		t.Fatalf("failed writing catalog: %v", err)
	}

	catalog, err := compliance.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// 2. Setup Validated Mapping RuleSet
	rulesetJSON := `{
		"schema_version": "1.0",
		"id": "felix-nist-persist-ruleset",
		"title": "FELIX to NIST SP 800-53 Persistence Ruleset",
		"version": "1.0.0",
		"target_catalog_id": "nist-sp800-53-persist-e2e",
		"target_catalog_version": "5.1.0",
		"rules": [
			{
				"id": "RULE-BOLA-AC3",
				"source_rule_id": "API_BOLA_IDOR",
				"target_control_id": "AC-3",
				"relationship": "direct",
				"rationale": "Object-level authorization bypass violates access enforcement.",
				"confidence": 0.95
			},
			{
				"id": "RULE-SQLI-SI10",
				"source_rule_id": "WEB_SQL_INJECTION",
				"target_control_id": "SI-10",
				"relationship": "direct",
				"rationale": "SQL injection violates input validation.",
				"confidence": 1.0
			}
		]
	}`

	rulesetPath := filepath.Join(tmpDir, "ruleset.json")
	if err := os.WriteFile(rulesetPath, []byte(rulesetJSON), 0644); err != nil {
		t.Fatalf("failed writing ruleset: %v", err)
	}

	ruleSet, err := compliance.LoadMappingRuleSet(rulesetPath)
	if err != nil {
		t.Fatalf("LoadMappingRuleSet failed: %v", err)
	}

	// 3. Generate Evaluation using EvaluationEngine
	findings := []report.Finding{
		{
			ID:           "F-AC3-BOLA-01",
			Source:       "apisec",
			RuleID:       "API_BOLA_IDOR",
			Category:     "authz",
			Title:        "BOLA on /api/accounts/400",
			Severity:     "HIGH",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "Unauthorized access to account 400 confirmed",
			Endpoint:     "/api/accounts/400",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
	}

	mappingResult, err := compliance.MapFindings(catalog, ruleSet, findings)
	if err != nil {
		t.Fatalf("MapFindings failed: %v", err)
	}

	evalContext := &compliance.EvaluationContext{
		AssessmentID:     "ASM-PERSIST-E2E-2026",
		ExecutionID:      "EXEC-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []compliance.PositiveEvidence{
			{
				ID:          "PE-SC13-TLS",
				ControlID:   "SC-13",
				Requirement: "transport_encryption",
				Observation: "TLS 1.3 enforced across all API endpoints",
				Method:      "ACTIVE_PROBE",
			},
		},
	}

	fixedClock := func() time.Time { return time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC) }
	engine := compliance.NewEvaluationEngine().WithClock(fixedClock)

	evalResult, err := engine.Evaluate(catalog, mappingResult, findings, evalContext)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// 4. Initialize SQLite Compliance Store on Disk
	dbPath := filepath.Join(tmpDir, "durable_compliance.db")
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	// 5. Save Evaluation Result Atomically
	if err := store.SaveEvaluationResult(evalResult); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// 6. Test Idempotent Retry (Identical repeated save succeeds with 0 duplicate rows)
	if err := store.SaveEvaluationResult(evalResult); err != nil {
		t.Fatalf("identical repeated SaveEvaluationResult failed: %v", err)
	}

	// 7. Verify Retrieval by Assessment and Catalog
	retrieved, err := store.GetEvaluationResult("ASM-PERSIST-E2E-2026", "nist-sp800-53-persist-e2e")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}

	if retrieved.Digest() != evalResult.Digest() {
		t.Errorf("retrieved Digest mismatch: %s vs %s", retrieved.Digest(), evalResult.Digest())
	}
	if len(retrieved.Evaluations) != 3 {
		t.Fatalf("expected 3 control evaluations, got %d", len(retrieved.Evaluations))
	}

	// Check individual control states:
	// AC-3: non_compliant (BOLA)
	// SI-10: not_assessed (no findings, no positive evidence)
	// SC-13: compliant (TLS 1.3)
	states := make(map[string]compliance.EvaluationState)
	for _, ev := range retrieved.Evaluations {
		states[ev.ControlID] = ev.State
	}

	if states["AC-3"] != compliance.StateNonCompliant {
		t.Errorf("expected AC-3 state=non_compliant, got %q", states["AC-3"])
	}
	if states["SI-10"] != compliance.StateNotAssessed {
		t.Errorf("expected SI-10 state=not_assessed, got %q", states["SI-10"])
	}
	if states["SC-13"] != compliance.StateCompliant {
		t.Errorf("expected SC-13 state=compliant, got %q", states["SC-13"])
	}

	// 8. Test Structured Evidence Query
	ac3EvalID := "eval:ASM-PERSIST-E2E-2026:nist-sp800-53-persist-e2e:AC-3"
	evLinks, err := store.GetEvaluationEvidence(ac3EvalID)
	if err != nil {
		t.Fatalf("GetEvaluationEvidence failed: %v", err)
	}
	if len(evLinks) == 0 {
		t.Errorf("expected evidence links for AC-3, got 0")
	}

	// 9. Test Query Filtering
	nonCompliantList, err := store.ListControlEvaluations(compliance.EvaluationFilter{
		AssessmentID: "ASM-PERSIST-E2E-2026",
		State:        compliance.StateNonCompliant,
	})
	if err != nil {
		t.Fatalf("ListControlEvaluations error: %v", err)
	}
	if len(nonCompliantList) != 1 || nonCompliantList[0].ControlID != "AC-3" {
		t.Errorf("expected 1 non_compliant control (AC-3), got %v", nonCompliantList)
	}

	// 10. Test Conflict Rejection (Attempting to mutate evaluation content under same assessment & catalog)
	conflictingResult, _ := engine.Evaluate(catalog, mappingResult, findings, evalContext)
	conflictingResult.Evaluations[0].Rationale = "ATTEMPTED MUTATION: unauthorized change"

	err = store.SaveEvaluationResult(conflictingResult)
	if err == nil || !errors.Is(err, compliance.ErrConflictingEvaluation) {
		t.Fatalf("expected ErrConflictingEvaluation for conflicting content, got: %v", err)
	}

	// 11. Test Restart/Reopen Durability
	if err := store.Close(); err != nil {
		t.Fatalf("failed closing store: %v", err)
	}

	reopenedStore, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer reopenedStore.Close()

	retrievedAfterRestart, err := reopenedStore.GetEvaluationResult("ASM-PERSIST-E2E-2026", "nist-sp800-53-persist-e2e")
	if err != nil {
		t.Fatalf("failed retrieving after restart: %v", err)
	}
	if retrievedAfterRestart.Digest() != evalResult.Digest() {
		t.Errorf("digest mutated across restart: %s vs %s", retrievedAfterRestart.Digest(), evalResult.Digest())
	}
	if !strings.Contains(retrievedAfterRestart.LimitationsNotice, "NOT constitute a formal regulatory certification") {
		t.Errorf("LimitationsNotice was lost in persistence")
	}
}
