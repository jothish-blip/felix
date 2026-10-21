package test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"felix/pkg/compliance"
)

func TestPhase97_MTTR_EndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "compliance_mttr_e2e.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating compliance store: %v", err)
	}

	clock := compliance.NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	startTime := clock.Now().UTC()

	// 1. Setup HMAC cryptographic key provider for Phase 9.5 integrity
	key, err := compliance.GenerateIntegrityKey("mttr-e2e-key")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	kp, err := compliance.NewStaticKeyProvider(key)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider failed: %v", err)
	}

	// 2. Persist signed evaluation result
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-MTTR-E2E",
		ExecutionID:     "EXEC-MTTR-001",
		CatalogIdentity: "nist-sp800-53-mttr-e2e:5.1.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		Summary: compliance.EvaluationSummary{
			TotalControls:      4,
			NonCompliantCount:  4,
			ApplicableControls: 4,
			AssessedControls:   4,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:   "eval:ASM-MTTR-E2E:SI-10",
				ControlID:      "SI-10",
				ControlTitle:   "Information Input Validation",
				CatalogID:      "nist-sp800-53-mttr-e2e",
				CatalogVersion: "5.1.0",
				AssessmentID:   "ASM-MTTR-E2E",
				State:          compliance.StateNonCompliant,
				Rationale:      "SQL injection vulnerability found in input handling.",
				FindingIDs:     []string{"F-MTTR-01"},
				EvaluatedAt:    startTime,
				EngineVersion:  "1.0.0",
			},
			{
				EvaluationID:   "eval:ASM-MTTR-E2E:SC-8",
				ControlID:      "SC-8",
				ControlTitle:   "Transmission Confidentiality and Integrity",
				CatalogID:      "nist-sp800-53-mttr-e2e",
				CatalogVersion: "5.1.0",
				AssessmentID:   "ASM-MTTR-E2E",
				State:          compliance.StateNonCompliant,
				Rationale:      "Weak TLS configuration.",
				FindingIDs:     []string{"F-MTTR-02"},
				EvaluatedAt:    startTime,
				EngineVersion:  "1.0.0",
			},
			{
				EvaluationID:   "eval:ASM-MTTR-E2E:SC-5",
				ControlID:      "SC-5",
				ControlTitle:   "Denial of Service Protection",
				CatalogID:      "nist-sp800-53-mttr-e2e",
				CatalogVersion: "5.1.0",
				AssessmentID:   "ASM-MTTR-E2E",
				State:          compliance.StateNonCompliant,
				Rationale:      "Diagnostic endpoint rate limiting issue.",
				FindingIDs:     []string{"F-MTTR-03"},
				EvaluatedAt:    startTime,
				EngineVersion:  "1.0.0",
			},
			{
				EvaluationID:   "eval:ASM-MTTR-E2E:SI-11",
				ControlID:      "SI-11",
				ControlTitle:   "Error Handling",
				CatalogID:      "nist-sp800-53-mttr-e2e",
				CatalogVersion: "5.1.0",
				AssessmentID:   "ASM-MTTR-E2E",
				State:          compliance.StateNonCompliant,
				Rationale:      "Server banner disclosed in responses.",
				FindingIDs:     []string{"F-MTTR-04"},
				EvaluatedAt:    startTime,
				EngineVersion:  "1.0.0",
			},
		},
		EvaluatedAt: startTime,
	}

	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	origDigest := evalRes.Digest()

	// 3. Configure corporate SLA policy
	policy := &compliance.RemediationSLAPolicy{
		ID:          "corp-mttr-policy",
		Version:     "1.0.0",
		Enabled:     true,
		Description: "Corporate MTTR test policy",
		Priority:    100,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
			"MEDIUM":   "30d",
			"LOW":      "90d",
		},
		DefaultRule: "30d",
	}
	if err := store.SaveRemediationPolicy(policy); err != nil {
		t.Fatalf("SaveRemediationPolicy failed: %v", err)
	}

	slaSvc := compliance.NewRemediationService(clock, 0)

	// 4. Finding 1 (CRITICAL): Completed in 18h (cycle 0), Reopened at 30h, Remediated again at 42h (cycle 1, 12h)
	rec1, evt1, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-MTTR-01",
		FindingTitle:    "Critical SQLi in Payment API",
		FindingSource:   "apisec",
		FindingCategory: "injection",
		AssessmentID:    "ASM-MTTR-E2E",
		CatalogID:       "nist-sp800-53-mttr-e2e:5.1.0",
		ControlID:       "SI-10",
		Severity:        "CRITICAL",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 1 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evt1); err != nil {
		t.Fatalf("SaveRemediationRecord 1 failed: %v", err)
	}

	// Cycle 0 completion at 18h
	clock.Set(startTime.Add(18 * time.Hour))
	evtDone1, err := slaSvc.TransitionStatus(rec1, compliance.RemediationStatusRemediated, "developer", "Hotfix deployed")
	if err != nil {
		t.Fatalf("TransitionStatus 1 Remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtDone1); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Remediated failed: %v", err)
	}

	// Reopen at 30h
	clock.Set(startTime.Add(30 * time.Hour))
	evtReopen1, err := slaSvc.TransitionStatus(rec1, compliance.RemediationStatusReopened, "qa-agent", "Regressed in staging")
	if err != nil {
		t.Fatalf("TransitionStatus 1 Reopened failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtReopen1); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Reopened failed: %v", err)
	}

	// Recalculate deadline for reopened cycle: 30h + 24h = 54h
	evtRecalc, err := slaSvc.RecalculateDeadline(rec1, policy, "qa-agent", "SLA recalculation for reopened hotfix")
	if err != nil {
		t.Fatalf("RecalculateDeadline 1 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtRecalc); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Recalculate failed: %v", err)
	}

	// Cycle 1 completion at 42h (12h duration)
	clock.Set(startTime.Add(42 * time.Hour))
	evtDone2, err := slaSvc.TransitionStatus(rec1, compliance.RemediationStatusRemediated, "developer", "Permanent fix verified")
	if err != nil {
		t.Fatalf("TransitionStatus 1 Re-remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec1, evtDone2); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Re-remediated failed: %v", err)
	}

	// 5. Finding 2 (HIGH): Completed late in 10 days (240h, deadline was 7d / 168h)
	rec2, evt2, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-MTTR-02",
		FindingTitle:    "Weak TLS Configuration",
		FindingSource:   "webvuln",
		FindingCategory: "crypto",
		AssessmentID:    "ASM-MTTR-E2E",
		CatalogID:       "nist-sp800-53-mttr-e2e:5.1.0",
		ControlID:       "SC-8",
		Severity:        "HIGH",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 2 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec2, evt2); err != nil {
		t.Fatalf("SaveRemediationRecord 2 failed: %v", err)
	}

	clock.Set(startTime.Add(10 * 24 * time.Hour))
	evtDoneLate, err := slaSvc.TransitionStatus(rec2, compliance.RemediationStatusRemediated, "sysadmin", "Ciphers updated")
	if err != nil {
		t.Fatalf("TransitionStatus 2 Remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec2, evtDoneLate); err != nil {
		t.Fatalf("SaveRemediationRecord 2 Remediated failed: %v", err)
	}

	// 6. Finding 3 (MEDIUM): Accepted Risk -> MUST NOT count as remediated
	rec3, evt3, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-MTTR-03",
		FindingTitle:    "Missing Rate Limiting on Internal Diagnostic Endpoint",
		FindingSource:   "apisec",
		FindingCategory: "dos",
		AssessmentID:    "ASM-MTTR-E2E",
		CatalogID:       "nist-sp800-53-mttr-e2e:5.1.0",
		ControlID:       "SC-5",
		Severity:        "MEDIUM",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 3 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec3, evt3); err != nil {
		t.Fatalf("SaveRemediationRecord 3 failed: %v", err)
	}

	clock.Set(startTime.Add(5 * 24 * time.Hour))
	riskExpiry := startTime.Add(90 * 24 * time.Hour)
	evtRisk, err := slaSvc.AcceptRisk(rec3, "Compensating firewall limits access to VPN only", "VP of Engineering", &riskExpiry, "VP of Engineering")
	if err != nil {
		t.Fatalf("AcceptRisk 3 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec3, evtRisk); err != nil {
		t.Fatalf("SaveRemediationRecord 3 AcceptRisk failed: %v", err)
	}

	// 7. Finding 4 (LOW): Remains Open
	rec4, evt4, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-MTTR-04",
		FindingTitle:    "Server Banner Leak",
		FindingSource:   "webvuln",
		FindingCategory: "info_leak",
		AssessmentID:    "ASM-MTTR-E2E",
		CatalogID:       "nist-sp800-53-mttr-e2e:5.1.0",
		ControlID:       "SI-11",
		Severity:        "LOW",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 4 failed: %v", err)
	}
	if err := store.SaveRemediationRecord(rec4, evt4); err != nil {
		t.Fatalf("SaveRemediationRecord 4 failed: %v", err)
	}

	// 8. Calculate MTTR
	mttrSvc := compliance.NewMTTRService(store, clock)
	result, err := mttrSvc.CalculateMTTR(context.Background(), compliance.MTTRFilter{
		KeyProvider: kp,
	})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	// Verification of MTTR metrics:
	// Episodes:
	// - F1 Cycle 0: 18h
	// - F1 Cycle 1: 12h
	// - F2 Cycle 0: 240h (10 days)
	// Total duration: 18h + 12h + 240h = 270h
	// Completed episodes = 3
	// Unique findings = 2 (F1, F2)
	// MTTR = 270h / 3 = 90h
	if !result.HasData {
		t.Fatalf("expected HasData = true")
	}
	if result.CompletedEpisodes != 3 {
		t.Errorf("expected 3 completed episodes, got %d", result.CompletedEpisodes)
	}
	if result.UniqueFindings != 2 {
		t.Errorf("expected 2 unique findings, got %d", result.UniqueFindings)
	}
	if result.TotalDuration != 270*time.Hour {
		t.Errorf("expected TotalDuration 270h, got %v", result.TotalDuration)
	}
	if result.MTTR != 90*time.Hour {
		t.Errorf("expected MTTR 90h, got %v", result.MTTR)
	}
	if result.MedianDuration == nil || *result.MedianDuration != 18*time.Hour {
		t.Errorf("expected MedianDuration 18h, got %v", result.MedianDuration)
	}
	if result.MinDuration == nil || *result.MinDuration != 12*time.Hour {
		t.Errorf("expected MinDuration 12h, got %v", result.MinDuration)
	}
	if result.MaxDuration == nil || *result.MaxDuration != 240*time.Hour {
		t.Errorf("expected MaxDuration 240h, got %v", result.MaxDuration)
	}

	// Exclusions:
	if result.Exclusions.OpenOrInProgress != 1 {
		t.Errorf("expected 1 open/in-progress exclusion (F4), got %d", result.Exclusions.OpenOrInProgress)
	}
	if result.Exclusions.AcceptedRisk != 1 {
		t.Errorf("expected 1 accepted-risk exclusion (F3), got %d", result.Exclusions.AcceptedRisk)
	}

	// SLA Performance:
	// 3 verifiable episodes: F1 cycle 0 (18h <= 24h, ON-TIME), F1 cycle 1 (12h <= 24h, ON-TIME), F2 (240h > 168h, LATE)
	// On-time = 2, Late = 1
	// Rate = 2/3 * 100 = 66.666...%
	sla := result.SLAPerformance
	if sla == nil {
		t.Fatalf("expected SLAPerformance, got nil")
	}
	if sla.VerifiableEpisodes != 3 {
		t.Errorf("expected 3 verifiable SLA episodes, got %d", sla.VerifiableEpisodes)
	}
	if sla.CompletedOnTime != 2 {
		t.Errorf("expected 2 completed on time, got %d", sla.CompletedOnTime)
	}
	if sla.CompletedLate != 1 {
		t.Errorf("expected 1 completed late, got %d", sla.CompletedLate)
	}
	if sla.OnTimeRate < 66.6 || sla.OnTimeRate > 66.7 {
		t.Errorf("expected ~66.7%% on-time rate, got %.2f%%", sla.OnTimeRate)
	}

	// 9. Close and reopen store to verify persistence
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	reopenedStore, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore reopen failed: %v", err)
	}
	defer reopenedStore.Close()

	reopenedSvc := compliance.NewMTTRService(reopenedStore, clock)
	reopenedResult, err := reopenedSvc.CalculateMTTR(context.Background(), compliance.MTTRFilter{
		KeyProvider: kp,
	})
	if err != nil {
		t.Fatalf("reopened CalculateMTTR failed: %v", err)
	}

	if reopenedResult.MTTR != 90*time.Hour || reopenedResult.CompletedEpisodes != 3 {
		t.Errorf("reopened store produced mismatched MTTR: %+v", reopenedResult)
	}

	// 10. Invariant verification: evaluation result and digest remain completely unmutated
	verRes, err := reopenedStore.VerifyEvaluationIntegrity("ASM-MTTR-E2E", "nist-sp800-53-mttr-e2e:5.1.0", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}
	if verRes.Status != compliance.StatusVerified {
		t.Errorf("compliance evaluation integrity compromised: status=%s, violations=%v", verRes.Status, verRes.Violations)
	}

	reopenedEval, err := reopenedStore.GetEvaluationResult("ASM-MTTR-E2E", "nist-sp800-53-mttr-e2e:5.1.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if reopenedEval.Digest() != origDigest {
		t.Errorf("evaluation digest mutated: expected %s, got %s", origDigest, reopenedEval.Digest())
	}

	// 11. Concurrency safety: 10 parallel goroutines calculating MTTR
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := reopenedSvc.CalculateMTTR(context.Background(), compliance.MTTRFilter{KeyProvider: kp})
			if err != nil || r.MTTR != 90*time.Hour {
				t.Errorf("concurrent CalculateMTTR failed: err=%v, r=%v", err, r)
			}
		}()
	}
	wg.Wait()
}
