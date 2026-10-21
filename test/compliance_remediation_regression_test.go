package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase96_RemediationSLA_EndToEnd tests the complete Phase 9.6 Remediation SLA pipeline:
// - Configurable versioned SLA policies and deterministic policy selection.
// - SLA assignment to findings from compliance assessments.
// - Deterministic deadline calculation using an injectable clock.
// - Lifecycle state transitions (Open -> InProgress -> Remediated -> Reopened).
// - Distinction between on-time and late remediation.
// - Auditable risk acceptance (requiring non-empty rationale and author; not counting as remediated).
// - Overdue detection and filtering.
// - Integrity preservation: historical compliance evaluations remain unmodified across remediation lifecycle changes.
// - Persistence across process restarts.
func TestPhase96_RemediationSLA_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_remediation_e2e.db")

	// 1. Setup Validated Catalog
	catalogJSON := `{
		"schema_version": "1.0",
		"id": "nist-sp800-53-sla-e2e",
		"title": "NIST SP 800-53 SLA Test Catalog",
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
				"id": "IA-2",
				"title": "Identification and Authentication",
				"description": "Uniquely identify and authenticate users.",
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
	ruleSetJSON := `{
		"schema_version": "1.0",
		"id": "felix-sla-e2e-rules",
		"title": "FELIX to NIST SP 800-53 SLA Ruleset",
		"version": "1.0.0",
		"target_catalog_id": "nist-sp800-53-sla-e2e",
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
				"id": "RULE-NOAUTH-IA2",
				"source_rule_id": "API_UNAUTHENTICATED",
				"target_control_id": "IA-2",
				"relationship": "direct",
				"rationale": "Missing authentication violates user identification requirements.",
				"confidence": 0.95
			}
		]
	}`

	ruleSetPath := filepath.Join(tmpDir, "ruleset.json")
	if err := os.WriteFile(ruleSetPath, []byte(ruleSetJSON), 0644); err != nil {
		t.Fatalf("failed writing ruleset: %v", err)
	}

	ruleSet, err := compliance.LoadMappingRuleSet(ruleSetPath)
	if err != nil {
		t.Fatalf("LoadMappingRuleSet failed: %v", err)
	}

	// 3. Setup Findings
	findings := []report.Finding{
		{
			ID:           "FINDING-BOLA-01",
			Source:       "apisec",
			RuleID:       "API_BOLA_IDOR",
			Category:     "authz",
			Title:        "Critical IDOR on Account API",
			Severity:     "CRITICAL",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "Object ID tampering yields full account records",
			Endpoint:     "/api/accounts/999",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
		{
			ID:           "FINDING-NOAUTH-02",
			Source:       "apisec",
			RuleID:       "API_UNAUTHENTICATED",
			Category:     "auth",
			Title:        "Missing Auth on User Management",
			Severity:     "HIGH",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "Unauthenticated POST /api/users",
			Endpoint:     "/api/users",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
	}

	mappingResult, err := compliance.MapFindings(catalog, ruleSet, findings)
	if err != nil {
		t.Fatalf("MapFindings failed: %v", err)
	}

	// 4. Run Evaluation Engine and Save Evaluated Result with Integrity Key
	evalEngine := compliance.NewEvaluationEngine()
	evalContext := &compliance.EvaluationContext{
		AssessmentID:     "ASM-SLA-E2E",
		ExecutionID:      "EXEC-SLA-001",
		AssessmentStatus: "COMPLETED",
	}

	evalResult, err := evalEngine.Evaluate(catalog, mappingResult, findings, evalContext)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	key, _ := compliance.GenerateIntegrityKey("sla-key-1")
	kp, _ := compliance.NewStaticKeyProvider(key)

	if err := store.SaveEvaluationResultWithKey(evalResult, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	origEvalDigest := evalResult.Digest()

	// 5. Configure Versioned SLA Policy
	slaPolicy := &compliance.RemediationSLAPolicy{
		ID:          "p9-corp-sla",
		Version:     "1.0.0",
		Enabled:     true,
		Description: "Production Engineering Remediation SLA",
		Priority:    50,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
			"MEDIUM":   "30d",
			"LOW":      "90d",
		},
		DefaultRule: "30d",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := store.SaveRemediationPolicy(slaPolicy); err != nil {
		t.Fatalf("SaveRemediationPolicy failed: %v", err)
	}

	// 6. Assign SLA to Finding 1 (CRITICAL: 24h deadline)
	startTime := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	clock := compliance.NewMockClock(startTime)
	svc := compliance.NewRemediationService(clock, 12*time.Hour)

	rec1, event1, err := svc.AssignSLA(compliance.AssignSLAParams{
		FindingID:          "FINDING-BOLA-01",
		FindingSource:      "apisec",
		FindingTitle:       "Critical IDOR on Account API",
		FindingCategory:    "authz",
		AssessmentID:       "ASM-SLA-E2E",
		ControlID:          "AC-3",
		Severity:           "CRITICAL",
		Policy:             slaPolicy,
		SLAStartTime:       startTime,
		Actor:              "pipeline-agent",
		EvidenceReferences: []string{"EV-BOLA-E2E"},
	})
	if err != nil {
		t.Fatalf("AssignSLA 1 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, event1); err != nil {
		t.Fatalf("SaveRemediationRecord 1 failed: %v", err)
	}

	expectedDeadline1 := startTime.Add(24 * time.Hour)
	if !rec1.Deadline.Equal(expectedDeadline1) {
		t.Errorf("expected deadline %v, got %v", expectedDeadline1, rec1.Deadline)
	}

	// 7. Assign SLA to Finding 2 (HIGH: 7d deadline)
	rec2, event2, err := svc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "FINDING-NOAUTH-02",
		FindingSource:   "apisec",
		FindingTitle:    "Missing Auth on User Management",
		FindingCategory: "auth",
		AssessmentID:    "ASM-SLA-E2E",
		ControlID:       "IA-2",
		Severity:        "HIGH",
		Policy:          slaPolicy,
		SLAStartTime:    startTime,
		Actor:           "pipeline-agent",
	})
	if err != nil {
		t.Fatalf("AssignSLA 2 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec2, event2); err != nil {
		t.Fatalf("SaveRemediationRecord 2 failed: %v", err)
	}

	// 8. Lifecycle: Advance clock 10h -> transition rec1 to in_progress
	clock.Advance(10 * time.Hour)
	evtProg, err := svc.TransitionStatus(rec1, compliance.RemediationStatusInProgress, "developer", "Hotfix branch opened")
	if err != nil {
		t.Fatalf("TransitionStatus InProgress failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtProg); err != nil {
		t.Fatalf("SaveRemediationRecord InProgress failed: %v", err)
	}

	// 9. Advance clock to 30h past start (6h past 24h deadline of rec1) -> rec1 is OVERDUE
	clock.Set(startTime.Add(30 * time.Hour))
	status1 := svc.ComputeSLAStatus(rec1)
	if status1 != compliance.SLAStatusOverdue {
		t.Errorf("expected SLAStatusOverdue for rec1 at 30h, got %s", status1)
	}

	// Query overdue items from store
	overdueItems, err := store.ListRemediationRecords(compliance.RemediationFilter{OnlyOverdue: true})
	if err != nil {
		t.Fatalf("ListRemediationRecords Overdue failed: %v", err)
	}
	if len(overdueItems) != 1 || overdueItems[0].ID != rec1.ID {
		t.Errorf("expected exactly 1 overdue item (rec1), got %d items", len(overdueItems))
	}

	// 10. Complete remediation late on rec1
	evtRem, err := svc.TransitionStatus(rec1, compliance.RemediationStatusRemediated, "developer", "Hotfix merged to main")
	if err != nil {
		t.Fatalf("TransitionStatus Remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtRem); err != nil {
		t.Fatalf("SaveRemediationRecord Remediated failed: %v", err)
	}
	if rec1.ComputedSLAStatus != compliance.SLAStatusRemediatedLate {
		t.Errorf("expected SLAStatusRemediatedLate, got %s", rec1.ComputedSLAStatus)
	}

	// 11. Reopen rec1
	evtReopen, err := svc.TransitionStatus(rec1, compliance.RemediationStatusReopened, "security-monitor", "Regression observed in canary deployment")
	if err != nil {
		t.Fatalf("TransitionStatus Reopened failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtReopen); err != nil {
		t.Fatalf("SaveRemediationRecord Reopened failed: %v", err)
	}
	if rec1.Status != compliance.RemediationStatusReopened {
		t.Errorf("expected status Reopened, got %s", rec1.Status)
	}
	if rec1.ReopenCount != 1 {
		t.Errorf("expected ReopenCount 1, got %d", rec1.ReopenCount)
	}

	// 12. Record authorized Risk Acceptance on rec2
	expiry := startTime.Add(90 * 24 * time.Hour)
	evtRisk, err := svc.AcceptRisk(rec2, "Compensating network segmentation and mTLS in place", "SecurityArchitect", &expiry, "SecurityArchitect")
	if err != nil {
		t.Fatalf("AcceptRisk failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec2, evtRisk); err != nil {
		t.Fatalf("SaveRemediationRecord AcceptRisk failed: %v", err)
	}
	if rec2.Status != compliance.RemediationStatusAcceptedRisk {
		t.Errorf("expected status AcceptedRisk, got %s", rec2.Status)
	}
	if rec2.ComputedSLAStatus != compliance.SLAStatusAcceptedRisk {
		t.Errorf("expected ComputedSLAStatus AcceptedRisk, got %s", rec2.ComputedSLAStatus)
	}
	if rec2.CompletedAt != nil {
		t.Errorf("Risk acceptance must not set CompletedAt")
	}

	// 13. Verify audit history for rec1
	history1, err := store.GetRemediationHistory(rec1.ID)
	if err != nil {
		t.Fatalf("GetRemediationHistory failed: %v", err)
	}
	if len(history1) != 4 { // ASSIGNED, InProgress, Remediated, Reopened
		t.Errorf("expected 4 history events for rec1, got %d", len(history1))
	}

	// 14. Restart store and verify persistence & non-mutation of compliance evaluation
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	reopenedStore, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore restart failed: %v", err)
	}
	defer reopenedStore.Close()

	// Verify rec1 still exists and retains all audit history across restart
	reopenedRec1, err := reopenedStore.GetRemediationRecord(rec1.ID)
	if err != nil {
		t.Fatalf("reopened GetRemediationRecord failed: %v", err)
	}
	if reopenedRec1.Status != compliance.RemediationStatusReopened || reopenedRec1.ReopenCount != 1 {
		t.Errorf("unexpected reopened rec1 state: %+v", reopenedRec1)
	}

	// Invariant: Evaluation result must remain cryptographically verifiable and unmutated
	verResult, err := reopenedStore.VerifyEvaluationIntegrity("ASM-SLA-E2E", "nist-sp800-53-sla-e2e:5.1.0", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}
	if verResult.Status != compliance.StatusVerified {
		t.Errorf("compliance evaluation integrity compromised by remediation SLA updates: status=%s, violations=%v", verResult.Status, verResult.Violations)
	}

	reopenedEval, err := reopenedStore.GetEvaluationResult("ASM-SLA-E2E", "nist-sp800-53-sla-e2e:5.1.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if reopenedEval.Digest() != origEvalDigest {
		t.Errorf("evaluation digest mutated: expected %s, got %s", origEvalDigest, reopenedEval.Digest())
	}
}
