package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"felix/pkg/verification"
)

// TestCLI_AssessmentVerify_CounterSemanticsAndOutputClarity verifies that the CLI
// displays distinct, unambiguous counters for:
// 1. Defended / unexposed controls (NOT_EXPOSED: 2)
// 2. Failed / ambiguous verification probes (Inconclusive Probes: 0)
// 3. Attempted verification rate calculated across attempted evaluations (5/7 = 71.4%)
func TestCLI_AssessmentVerify_CounterSemanticsAndOutputClarity(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_verify_semantics_test.db")
	t.Setenv("FELIX_DB_PATH", dbPath)

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	clientID := "client-semantics-01"
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Semantics Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asmID := "asm-semantics-01"
	asmRef := "ASM-2026-TEST"
	err = store.CreateAssessment(&assessment.Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Semantics Verification Audit",
		Status:    assessment.StatusCompleted,
		ScopeMode: "same-origin",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	execID := "exec-semantics-01"
	now := time.Now().UTC()
	err = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})
	if err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	sumObj := verification.VerificationSummary{
		TotalFindings:             7,
		AttemptedCount:            7,
		VerifiedCount:             5,
		DetectedCount:             0,
		ObservedCount:             0,
		NotVerifiedCount:          0,
		NotExposedCount:           2,
		BlockedCount:              0,
		InconclusiveCount:         0,
		SyntheticCount:            0,
		ConfirmationRate:          71.4,
		ConclusiveCount:           7,
		ConclusiveRate:            100.0,
		AttemptRate:               100.0,
		VerificationRateAttempted: 71.4,
		VerificationRateTotal:     71.4,
	}
	covBytes, _ := json.Marshal(sumObj)

	// Record Verification Summary: 7 findings total, 5 VERIFIED, 2 NOT_EXPOSED, 0 Inconclusive probes
	verRun := &verification.VerificationRunRecord{
		ID:                "ver-run-semantics-01",
		AssessmentID:      asmID,
		ExecutionID:       execID,
		TotalFindings:     7,
		AttemptedCount:    7,
		VerifiedCount:     5,
		DetectedCount:     0,
		ObservedCount:     0,
		NotVerifiedCount:  0,
		NotExposedCount:   2,
		BlockedCount:      0,
		InconclusiveCount: 0,
		SyntheticCount:    0,
		CoverageJSON:      string(covBytes),
		VerifierVersion:   "2.0",
		CreatedAt:         now,
	}
	if err := store.SaveVerificationRun(verRun); err != nil {
		t.Fatalf("failed to save verification run: %v", err)
	}

	results := []verification.VerificationResult{
		{
			ID:                     "ver-1",
			FindingID:              "f-1",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusVerified,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-2",
			FindingID:              "f-2",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusVerified,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-3",
			FindingID:              "f-3",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusNotExposed,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-4",
			FindingID:              "f-4",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusNotExposed,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-5",
			FindingID:              "f-5",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusVerified,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-6",
			FindingID:              "f-6",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusVerified,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
		{
			ID:                     "ver-7",
			FindingID:              "f-7",
			AssessmentID:           asmID,
			ExecutionID:            execID,
			Status:                 verification.StatusVerified,
			PolicyID:               "POL-APISEC-01",
			Attempted:              true,
			DetectionConfidence:    "HIGH",
			VerificationConfidence: "HIGH",
			OverallConfidence:      "HIGH",
			CompletedAt:            now,
		},
	}
	if err := store.SaveVerificationResults(asmID, execID, results); err != nil {
		t.Fatalf("failed to save verification results: %v", err)
	}

	// 1. Test Text CLI Output
	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentVerify([]string{asmRef})
	})
	if code != 0 {
		t.Fatalf("runAssessmentVerify returned %d (stderr: %s)", code, errOut)
	}

	expectedHeader := "Total Findings: 7  |  Verified: 5  |  Detected: 0  |  Not Verified: 0  |  Not Exposed: 2"
	if !strings.Contains(out, expectedHeader) {
		t.Errorf("expected output to contain %q, got:\n%s", expectedHeader, out)
	}

	expectedBreakdown := "Confirmation Rate: 71.4% (5/7 confirmed)  |  Conclusive Rate: 100.0% (7/7 conclusive)  |  Inconclusive Probes: 0"
	if !strings.Contains(out, expectedBreakdown) {
		t.Errorf("expected output to contain %q, got:\n%s", expectedBreakdown, out)
	}

	expectedRate := "Verification Rate: 71.4% (Attempted: 7, Blocked: 0, Inconclusive Probes: 0)"
	if !strings.Contains(out, expectedRate) {
		t.Errorf("expected output to contain %q, got:\n%s", expectedRate, out)
	}

	// 2. Test JSON CLI Output
	codeJSON, outJSON, errOutJSON := captureStdoutStderr(func() int {
		return runAssessmentVerify([]string{asmRef, "--json"})
	})
	if codeJSON != 0 {
		t.Fatalf("runAssessmentVerify --json returned %d (stderr: %s)", codeJSON, errOutJSON)
	}

	var jsonResult struct {
		AssessmentRef string `json:"assessment_ref"`
		Summary       struct {
			TotalFindings              int     `json:"total_findings"`
			AttemptedCount             int     `json:"attempted_count"`
			VerifiedCount              int     `json:"verified_count"`
			NotExposedCount            int     `json:"not_exposed_count"`
			InconclusiveCount          int     `json:"inconclusive_count"`
			BlockedCount               int     `json:"blocked_count"`
			VerificationRateAttempted  float64 `json:"verification_rate_attempted"`
			ConfirmationRate           float64 `json:"confirmation_rate"`
			ConclusiveCount            int     `json:"conclusive_count"`
			ConclusiveRate             float64 `json:"conclusive_rate"`
			AttemptRate                float64 `json:"attempt_rate"`
		} `json:"summary"`
		VerificationResults []verification.VerificationResult `json:"verification_results"`
	}

	if err := json.Unmarshal([]byte(outJSON), &jsonResult); err != nil {
		t.Fatalf("failed to unmarshal CLI json output: %v\nOutput:\n%s", err, outJSON)
	}

	if jsonResult.AssessmentRef != asmRef {
		t.Errorf("expected assessment_ref %s, got %s", asmRef, jsonResult.AssessmentRef)
	}
	if jsonResult.Summary.TotalFindings != 7 {
		t.Errorf("expected total_findings 7, got %d", jsonResult.Summary.TotalFindings)
	}
	if jsonResult.Summary.VerifiedCount != 5 {
		t.Errorf("expected verified_count 5, got %d", jsonResult.Summary.VerifiedCount)
	}
	if jsonResult.Summary.NotExposedCount != 2 {
		t.Errorf("expected not_exposed_count 2, got %d", jsonResult.Summary.NotExposedCount)
	}
	if jsonResult.Summary.InconclusiveCount != 0 {
		t.Errorf("expected inconclusive_count 0, got %d", jsonResult.Summary.InconclusiveCount)
	}
	if jsonResult.Summary.ConfirmationRate != 71.4 {
		t.Errorf("expected confirmation_rate 71.4, got %.1f", jsonResult.Summary.ConfirmationRate)
	}
	if jsonResult.Summary.ConclusiveCount != 7 {
		t.Errorf("expected conclusive_count 7, got %d", jsonResult.Summary.ConclusiveCount)
	}
	if jsonResult.Summary.ConclusiveRate != 100.0 {
		t.Errorf("expected conclusive_rate 100.0, got %.1f", jsonResult.Summary.ConclusiveRate)
	}
	if jsonResult.Summary.AttemptRate != 100.0 {
		t.Errorf("expected attempt_rate 100.0, got %.1f", jsonResult.Summary.AttemptRate)
	}
	if jsonResult.Summary.VerificationRateAttempted != 71.4 {
		t.Errorf("expected verification_rate_attempted 71.4, got %.1f", jsonResult.Summary.VerificationRateAttempted)
	}
	if len(jsonResult.VerificationResults) != 7 {
		t.Errorf("expected 7 verification_results, got %d", len(jsonResult.VerificationResults))
	}
}

// TestCLI_SnapshotImmutability_SaveFindingsRejectedOnCompletedSnapshot verifies
// that once a snapshot is marked complete (is_complete = 1), SaveFindings strictly
// returns ErrSnapshotImmutable and refuses in-place mutation.
func TestCLI_SnapshotImmutability_SaveFindingsRejectedOnCompletedSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_immutability_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	clientID := "client-imm-01"
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Immutability Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asmID := "asm-imm-01"
	_ = store.CreateAssessment(&assessment.Assessment{
		ID:        asmID,
		Ref:       "ASM-IMM-01",
		ClientID:  clientID,
		Name:      "Immutability Test Assessment",
		Status:    assessment.StatusCompleted,
		ScopeMode: "same-origin",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	execID := "exec-imm-01"
	now := time.Now().UTC()
	err = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})
	if err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	targetID := "tgt-imm-01"
	err = store.AddTarget(&assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "http://127.0.0.1:8080/test",
		ScopeStatus:  "APPROVED",
	})
	if err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	initialFinding := assessment.AssessmentFinding{
		ID:                 "fnd-imm-01",
		AssessmentID:       asmID,
		ExecutionID:        execID,
		TargetID:           targetID,
		Title:              "Initial Finding",
		Category:           "missing-csp",
		Severity:           "LOW",
		VerificationStatus: report.VerificationDetected,
		CreatedAt:          now,
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{initialFinding}); err != nil {
		t.Fatalf("initial SaveFindings failed: %v", err)
	}

	// Create completed snapshot
	snapshot := &assessment.AssessmentSnapshot{
		ID:            "snp-imm-01",
		SnapshotRef:   "SNP-IMM-01",
		AssessmentID:  asmID,
		ExecutionID:   execID,
		ClientID:      clientID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		ScopedTargets: []string{"http://127.0.0.1:8080/test"},
		FindingCount:  1,
		CreatedAt:     now,
	}
	if err := store.CreateSnapshot(snapshot, []assessment.AssessmentFinding{initialFinding}, nil); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Attempt mutation on completed snapshot execution
	mutatedFinding := initialFinding
	mutatedFinding.VerificationStatus = report.VerificationVerified
	mutatedFinding.Severity = "HIGH"

	err = store.SaveFindings([]assessment.AssessmentFinding{mutatedFinding})
	if err == nil {
		t.Fatalf("expected ErrSnapshotImmutable when mutating finding on completed snapshot, got nil")
	}
	if !errors.Is(err, assessment.ErrSnapshotImmutable) {
		t.Errorf("expected ErrSnapshotImmutable, got: %v", err)
	}

	// Verify the original snapshot was preserved
	storedSnap, err := store.GetSnapshot("snp-imm-01", assessment.NewClientAuthContext(clientID))
	if err != nil {
		t.Fatalf("GetSnapshot failed: %v", err)
	}
	if !storedSnap.IsComplete {
		t.Errorf("expected snapshot IsComplete to be true")
	}
	if storedSnap.FindingCount != 1 {
		t.Errorf("expected snapshot FindingCount 1, got %d", storedSnap.FindingCount)
	}
}

// TestCLI_FindingStatusVsVerificationReconciliation verifies that finding lifecycle
// status INCONCLUSIVE (defended route / barrier) and verification outcome NOT_EXPOSED
// reconcile cleanly across report summary and verification engine metrics.
func TestCLI_FindingStatusVsVerificationReconciliation(t *testing.T) {
	rep := &report.Report{
		Findings: []report.Finding{
			{
				ID:       "f-1",
				Title:    "Missing CSP",
				Status:   report.FindingStatusConfirmed,
				Severity: report.SeverityLow,
				Verification: report.VerificationRecord{
					Status:    report.VerificationVerified,
					Attempted: true,
				},
			},
			{
				ID:       "f-2",
				Title:    "Restricted Telescope Interface",
				Status:   report.FindingStatusInconclusive,
				Severity: report.SeverityInfo,
				Verification: report.VerificationRecord{
					Status:    report.VerificationNotExposed,
					Attempted: true,
				},
			},
		},
	}

	s := report.Summarize(rep.Findings)

	// In finding lifecycle domain:
	if s.ConfirmedCount != 1 {
		t.Errorf("expected 1 CONFIRMED finding, got %d", s.ConfirmedCount)
	}
	if s.InconclusiveStatusCount != 1 {
		t.Errorf("expected 1 INCONCLUSIVE finding, got %d", s.InconclusiveStatusCount)
	}

	// In verification outcome domain:
	if s.VerifiedCount != 1 {
		t.Errorf("expected 1 VERIFIED verification, got %d", s.VerifiedCount)
	}
	if s.NotExposedCount != 1 {
		t.Errorf("expected 1 NOT_EXPOSED verification, got %d", s.NotExposedCount)
	}
	if s.AttemptedCount != 2 {
		t.Errorf("expected 2 Attempted verifications, got %d", s.AttemptedCount)
	}
	// 1 verified out of 2 attempted = 50.0%
	if s.VerificationRateAttempted != 50.0 {
		t.Errorf("expected 50.0%% verification rate, got %.1f%%", s.VerificationRateAttempted)
	}
	if s.ConfirmationRate != 50.0 {
		t.Errorf("expected 50.0%% confirmation rate, got %.1f%%", s.ConfirmationRate)
	}
	if s.ConclusiveCount != 2 {
		t.Errorf("expected 2 conclusive findings, got %d", s.ConclusiveCount)
	}
	if s.ConclusiveRate != 100.0 {
		t.Errorf("expected 100.0%% conclusive rate, got %.1f%%", s.ConclusiveRate)
	}
	if s.AttemptRate != 100.0 {
		t.Errorf("expected 100.0%% attempt rate, got %.1f%%", s.AttemptRate)
	}
}

// TestVerificationRates_ZeroDenominator_Blocked_Unattempted_NotExposed tests edge cases:
// 1. Zero denominator: Total=0, Attempted=0 -> all rates safe 0.0
// 2. Unattempted findings: Total=7, Attempted=5, Unattempted=2 -> AttemptRate=71.4%
// 3. Blocked findings: BlockedCount=1 tracked under safety policy
// 4. NOT_EXPOSED outcomes: Conclusive verification rate reflects verified + not_exposed
func TestVerificationRates_ZeroDenominator_Blocked_Unattempted_NotExposed(t *testing.T) {
	// Case 1: Zero denominator
	emptySum := report.Summarize(nil)
	if emptySum.AttemptRate != 0.0 || emptySum.ConfirmationRate != 0.0 || emptySum.ConclusiveRate != 0.0 ||
		emptySum.VerificationRateAttempted != 0.0 || emptySum.VerificationRateTotal != 0.0 {
		t.Errorf("expected all rates 0.0 on zero denominator, got: attempt=%.1f conf=%.1f concl=%.1f verAtt=%.1f verTot=%.1f",
			emptySum.AttemptRate, emptySum.ConfirmationRate, emptySum.ConclusiveRate,
			emptySum.VerificationRateAttempted, emptySum.VerificationRateTotal)
	}

	// Case 2: Mixed unattempted, blocked, verified, and not_exposed
	findings := []report.Finding{
		// 3 Confirmed / Verified
		{ID: "f1", Status: report.FindingStatusConfirmed, Severity: report.SeverityHigh, Verification: report.VerificationRecord{Status: report.VerificationVerified, Attempted: true}},
		{ID: "f2", Status: report.FindingStatusConfirmed, Severity: report.SeverityMedium, Verification: report.VerificationRecord{Status: report.VerificationVerified, Attempted: true}},
		{ID: "f3", Status: report.FindingStatusConfirmed, Severity: report.SeverityLow, Verification: report.VerificationRecord{Status: report.VerificationVerified, Attempted: true}},
		// 2 Not Exposed (Defended controls)
		{ID: "f4", Status: report.FindingStatusInconclusive, Severity: report.SeverityInfo, Verification: report.VerificationRecord{Status: report.VerificationNotExposed, Attempted: true}},
		{ID: "f5", Status: report.FindingStatusInconclusive, Severity: report.SeverityInfo, Verification: report.VerificationRecord{Status: report.VerificationNotExposed, Attempted: true}},
		// 1 Safety Policy Blocked (Attempted check was intercepted and blocked)
		{ID: "f6", Status: report.FindingStatusSuspected, Severity: report.SeverityMedium, Verification: report.VerificationRecord{Status: report.VerificationNotVerified, Attempted: true, Result: "Probe blocked by safety policy"}},
		// 1 Unattempted Heuristic / Observation
		{ID: "f7", Status: report.FindingStatusSuspected, Severity: report.SeverityInfo, Verification: report.VerificationRecord{Status: report.VerificationObserved, Attempted: false}},
	}

	s := report.Summarize(findings)

	if s.TotalFindings != 7 {
		t.Errorf("expected TotalFindings 7, got %d", s.TotalFindings)
	}
	if s.AttemptedCount != 6 {
		t.Errorf("expected AttemptedCount 6, got %d", s.AttemptedCount)
	}
	if s.VerifiedCount != 3 {
		t.Errorf("expected VerifiedCount 3, got %d", s.VerifiedCount)
	}
	if s.NotExposedCount != 2 {
		t.Errorf("expected NotExposedCount 2, got %d", s.NotExposedCount)
	}
	if s.BlockedCount != 1 {
		t.Errorf("expected BlockedCount 1, got %d", s.BlockedCount)
	}
	if s.ConclusiveCount != 5 { // 3 verified + 2 not_exposed
		t.Errorf("expected ConclusiveCount 5, got %d", s.ConclusiveCount)
	}

	// Attempt rate: 6 / 7 = 85.7%
	if s.AttemptRate != 85.7 {
		t.Errorf("expected AttemptRate 85.7%%, got %.1f%%", s.AttemptRate)
	}
	// Confirmation rate: 3 / 6 = 50.0%
	if s.ConfirmationRate != 50.0 {
		t.Errorf("expected ConfirmationRate 50.0%%, got %.1f%%", s.ConfirmationRate)
	}
	// Conclusive verification rate: 5 / 6 = 83.3%
	if s.ConclusiveRate != 83.3 {
		t.Errorf("expected ConclusiveRate 83.3%%, got %.1f%%", s.ConclusiveRate)
	}
	// Backwards compatibility VerificationRateAttempted: 3 / 6 = 50.0%
	if s.VerificationRateAttempted != 50.0 {
		t.Errorf("expected VerificationRateAttempted 50.0%%, got %.1f%%", s.VerificationRateAttempted)
	}
}
