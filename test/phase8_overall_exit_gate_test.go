package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/ci"
	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/provenance"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// TestPhase8_ExitGate_Comprehensive verifies all 12 Phase 8 cross-work-package integration contracts end-to-end.
func TestPhase8_ExitGate_Comprehensive(t *testing.T) {
	// Setup isolated SQLite store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "phase8_gate.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{
		ID:        "client-p8",
		Name:      "Phase 8 Integration Client",
		CreatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-p8",
		ClientID:       client.ID,
		Ref:            "ASM-P8-01",
		AssessmentType: assessment.AssessmentTypeWebSecurity,
		Status:         assessment.StatusReady,
		CreatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	// -------------------------------------------------------------------------
	// Contract 1: Clean execution
	// assessment succeeds, policy passes, artifacts are valid, provenance is retained,
	// and the final classification is success (exit code 0).
	// -------------------------------------------------------------------------
	t.Run("Contract 1: Clean Execution", func(t *testing.T) {
		maxCrit := 0
		maxHigh := 2
		pol := &policy.ThresholdPolicy{
			Version:     "1.0",
			Name:        "Strict Clean Policy",
			MaxCritical: &maxCrit,
			MaxHigh:     &maxHigh,
		}

		cleanFindings := []report.Finding{
			{
				ID:          "f-clean-low-1",
				Severity:    report.SeverityLow,
				Title:       "Informational TLS hint",
				Endpoint:    "https://example.com/info",
				Fingerprint: "fp-clean-1",
			},
		}

		evalCtx := policy.EvaluationContext{
			AssessmentID: asm.ID,
			TenantID:     client.ID,
			Status:       "COMPLETED",
			TargetScope:  []string{"https://example.com"},
		}

		dec, err := policy.EvaluatePolicy(pol, cleanFindings, evalCtx)
		if err != nil {
			t.Fatalf("clean policy evaluation failed: %v", err)
		}
		if !dec.Passed || !dec.Reliable {
			t.Fatalf("expected policy to pass reliably, got passed=%v reliable=%v", dec.Passed, dec.Reliable)
		}

		cls := clierror.ClassifyAssessment("COMPLETED", nil, false, nil)
		if cls.ExitCode() != 0 {
			t.Fatalf("expected Exit 0 for clean execution, got %d (%s)", cls.ExitCode(), cls.Category)
		}
		if cls.Category != clierror.CategorySuccess {
			t.Errorf("expected CategorySuccess, got %s", cls.Category)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 2: Policy violation
	// an eligible completed assessment violates configured threshold;
	// decision is explainable and expected security-failure exit code (1) is preserved.
	// -------------------------------------------------------------------------
	t.Run("Contract 2: Policy Violation", func(t *testing.T) {
		maxCrit := 0
		pol := &policy.ThresholdPolicy{
			Version:     "1.0",
			Name:        "Zero Critical Policy",
			MaxCritical: &maxCrit,
		}

		violatingFindings := []report.Finding{
			{
				ID:          "f-crit-1",
				Severity:    report.SeverityCritical,
				Title:       "SQL Injection in login",
				Endpoint:    "https://example.com/login",
				Fingerprint: "fp-crit-1",
			},
		}

		evalCtx := policy.EvaluationContext{
			AssessmentID: asm.ID,
			TenantID:     client.ID,
			Status:       "COMPLETED",
			TargetScope:  []string{"https://example.com"},
		}

		dec, err := policy.EvaluatePolicy(pol, violatingFindings, evalCtx)
		if err != nil {
			t.Fatalf("eval failed: %v", err)
		}
		if dec.Passed {
			t.Fatal("expected policy violation, but policy passed!")
		}
		if len(dec.Violations) == 0 {
			t.Fatal("expected explainable violations, got none")
		}
		if dec.Violations[0].Severity != "CRITICAL" {
			t.Errorf("expected CRITICAL in violation, got: %s", dec.Violations[0].Severity)
		}

		cls := clierror.ClassifyAssessment("COMPLETED", nil, true, nil)
		if cls.ExitCode() != 1 {
			t.Fatalf("expected Exit 1 for security violation, got %d", cls.ExitCode())
		}
		if cls.Category != clierror.CategorySecurityViolation {
			t.Errorf("expected CategorySecurityViolation, got %s", cls.Category)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 3: Policy violation plus secondary failure
	// report export or PR feedback fails after policy violation is established;
	// primary classification remains correct (Exit 1).
	// -------------------------------------------------------------------------
	t.Run("Contract 3: Policy Violation Takes Precedence Over Secondary Failure", func(t *testing.T) {
		reportExportErr := os.ErrPermission
		secondaryFeedbackErr := fmt.Errorf("GitHub API rate limit 429")

		cls := clierror.ClassifyAssessment("COMPLETED", nil, true, nil, reportExportErr, secondaryFeedbackErr)
		if cls.ExitCode() != 1 {
			t.Fatalf("expected Exit 1 (policy violation preserved) despite secondary errors, got %d", cls.ExitCode())
		}
		if cls.Category != clierror.CategorySecurityViolation {
			t.Errorf("expected CategorySecurityViolation, got %s", cls.Category)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 4: Clean assessment plus artifact failure
	// required output generation fails and result is classified as operational failure (Exit 2).
	// -------------------------------------------------------------------------
	t.Run("Contract 4: Clean Assessment Plus Artifact Failure", func(t *testing.T) {
		artifactErr := fmt.Errorf("failed writing SARIF file: disk full")

		cls := clierror.ClassifyAssessment("COMPLETED", nil, false, nil, artifactErr)
		if cls.ExitCode() != 2 {
			t.Fatalf("expected Exit 2 for operational artifact failure, got %d", cls.ExitCode())
		}
		if cls.Category != clierror.CategoryToolFailure {
			t.Errorf("expected CategoryToolFailure, got %s", cls.Category)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 5: Primary assessment failure
	// engine execution fails; partial findings cannot manufacture a passing or failing decision.
	// -------------------------------------------------------------------------
	t.Run("Contract 5: Primary Assessment Engine Failure", func(t *testing.T) {
		// Crawl / engine failure marked as COMPLETED_WITH_ERRORS or FAILED
		cls := clierror.ClassifyAssessment("COMPLETED_WITH_ERRORS", nil, true, nil)
		if cls.ExitCode() != 2 {
			t.Fatalf("expected Exit 2 for incomplete crawl/engine error, got %d", cls.ExitCode())
		}
		if cls.Category != clierror.CategoryIncomplete {
			t.Errorf("expected CategoryIncomplete, got %s", cls.Category)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 6: Interrupted execution
	// cancellation or interruption is not treated as success, cannot establish a valid baseline,
	// and cannot produce false resolved findings.
	// -------------------------------------------------------------------------
	t.Run("Contract 6: Interrupted Execution Ineligible as Baseline", func(t *testing.T) {
		now := time.Now().UTC()
		interruptedExec := &assessment.AssessmentExecution{
			ID:               "exec-gate-interrupted",
			AssessmentID:     asm.ID,
			ClientID:         client.ID,
			InitiationSource: "manual",
			Status:           assessment.StatusInterrupted,
			StartedAt:        now.Add(-5 * time.Minute),
			CompletedAt:      &now,
		}
		_ = store.CreateExecution(interruptedExec)

		ctrl := assessment.NewController(store)
		_, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
			BaselineRef: interruptedExec.ID,
		})
		if err == nil {
			t.Fatal("expected RunAssessment to reject interrupted baseline, but succeeded!")
		}
		if !strings.Contains(err.Error(), "ineligible baseline") {
			t.Errorf("expected error mentioning ineligible baseline, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 7: Baseline comparison
	// valid completed baseline data produces correct deltas and expected evaluation scope.
	// -------------------------------------------------------------------------
	t.Run("Contract 7: Baseline Comparison Deltas and Scopes", func(t *testing.T) {
		tgt := &assessment.AssessmentTarget{
			ID:           "tgt-gate-1",
			AssessmentID: asm.ID,
			TargetURL:    "https://example.com",
			ScopeStatus:  "APPROVED",
		}
		_ = store.AddTarget(tgt)

		now := time.Now().UTC()
		baseExec := &assessment.AssessmentExecution{
			ID:               "exec-gate-base-valid",
			AssessmentID:     asm.ID,
			ClientID:         client.ID,
			InitiationSource: "manual",
			Status:           assessment.StatusCompleted,
			StartedAt:        now.Add(-10 * time.Minute),
			CompletedAt:      &now,
			FindingCount:     2,
		}
		_ = store.CreateExecution(baseExec)

		fPersistent := report.Finding{
			ID:          "f-base-1",
			Severity:    report.SeverityHigh,
			Title:       "Persistent Vuln",
			Endpoint:    "https://example.com/vuln",
			Fingerprint: "fp-shared-1",
		}
		fResolved := report.Finding{
			ID:          "f-base-2",
			Severity:    report.SeverityMedium,
			Title:       "Resolved Vuln",
			Endpoint:    "https://example.com/resolved",
			Fingerprint: "fp-resolved-2",
		}

		baseAFs := []assessment.AssessmentFinding{
			assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fPersistent),
			assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fResolved),
		}
		_ = store.SaveFindings(baseAFs)
		snap := assessment.BuildAssessmentSnapshot(asm, baseExec, []string{tgt.TargetURL}, baseAFs, true)
		snap.SetAssessedTargets([]string{tgt.TargetURL})
		_ = store.CreateSnapshot(snap, baseAFs, nil)

		// Current execution with persistent finding and brand new finding
		currExec := &assessment.AssessmentExecution{
			ID:               "exec-gate-curr-valid",
			AssessmentID:     asm.ID,
			ClientID:         client.ID,
			InitiationSource: "manual",
			Status:           assessment.StatusCompleted,
			StartedAt:        now,
			CompletedAt:      &now,
			FindingCount:     2,
		}
		_ = store.CreateExecution(currExec)

		fNew := report.Finding{
			ID:          "f-curr-3",
			Severity:    report.SeverityCritical,
			Title:       "Brand New Critical Vuln",
			Endpoint:    "https://example.com/new",
			Fingerprint: "fp-new-3",
		}
		currAFs := []assessment.AssessmentFinding{
			assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fPersistent),
			assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fNew),
		}
		_ = store.SaveFindings(currAFs)
		currSnap := assessment.BuildAssessmentSnapshot(asm, currExec, []string{tgt.TargetURL}, currAFs, true)
		currSnap.SetAssessedTargets([]string{tgt.TargetURL})
		_ = store.CreateSnapshot(currSnap, currAFs, nil)

		// Calculate change summary
		authAdmin := assessment.NewAdminAuthContext()
		changeSummary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
		}
		if changeSummary.Counts.Persistent != 1 {
			t.Errorf("expected 1 persistent finding, got %d", changeSummary.Counts.Persistent)
		}
		if changeSummary.Counts.Resolved != 1 {
			t.Errorf("expected 1 resolved finding, got %d", changeSummary.Counts.Resolved)
		}
		if changeSummary.Counts.New != 1 {
			t.Errorf("expected 1 new finding, got %d", changeSummary.Counts.New)
		}

		// Policy evaluation with scope: new
		maxCrit := 0
		polNewOnly := &policy.ThresholdPolicy{
			Version:         "1.0",
			Name:            "New Only Policy",
			EvaluationScope: "new",
			MaxCritical:     &maxCrit,
		}
		evalCtx := policy.EvaluationContext{
			AssessmentID:       asm.ID,
			TenantID:           client.ID,
			Status:             "COMPLETED",
			TargetScope:        []string{"https://example.com"},
			BaselineComparison: changeSummary,
		}
		dec, err := policy.EvaluatePolicy(polNewOnly, []report.Finding{fPersistent, fNew}, evalCtx)
		if err != nil {
			t.Fatalf("policy evaluation with baseline failed: %v", err)
		}
		// fNew is new critical -> policy must fail on new critical
		if dec.Passed {
			t.Errorf("expected policy to fail on new critical finding in scope new")
		}
	})

	// -------------------------------------------------------------------------
	// Contract 8: SARIF output schema conformance
	// normal and incomplete results validate against official OASIS SARIF 2.1.0 schema.
	// -------------------------------------------------------------------------
	t.Run("Contract 8: SARIF OASIS 2.1.0 Conformance", func(t *testing.T) {
		// Completed report
		completeRep := report.Report{
			Version:          "1.0.0",
			Target:           "https://example.com",
			CompletionStatus: "COMPLETED",
			Findings: []report.Finding{
				{
					ID:       "fnd-sarif-1",
					Title:    "Valid finding",
					Severity: "HIGH",
					RuleID:   "FELIX-SEC-001",
					Provenance: &report.EvidenceProvenance{
						Location: "config/jwt.go:42",
					},
				},
			},
		}
		sarifComplete, err := report.GenerateSARIF(completeRep)
		if err != nil {
			t.Fatalf("GenerateSARIF complete failed: %v", err)
		}
		completeFile := filepath.Join(tmpDir, "complete.sarif")
		_ = os.WriteFile(completeFile, sarifComplete, 0644)
		if err := report.ValidateSARIFFile(completeFile); err != nil {
			t.Fatalf("complete SARIF failed schema validation: %v", err)
		}

		// Incomplete / partial report
		partialRep := report.Report{
			Version:          "1.0.0",
			Target:           "https://example.com",
			CompletionStatus: "INTERRUPTED",
			Metadata: map[string]any{
				"is_partial": true,
			},
			Findings: []report.Finding{
				{
					ID:       "fnd-partial-1",
					Title:    "Interrupted finding",
					Severity: "MEDIUM",
				},
			},
		}
		sarifPartial, err := report.GenerateSARIF(partialRep)
		if err != nil {
			t.Fatalf("GenerateSARIF partial failed: %v", err)
		}
		partialFile := filepath.Join(tmpDir, "partial.sarif")
		_ = os.WriteFile(partialFile, sarifPartial, 0644)
		if err := report.ValidateSARIFFile(partialFile); err != nil {
			t.Fatalf("partial SARIF failed schema validation: %v", err)
		}

		// Verify invocations executionSuccessful is false for partial
		var partialLog report.SARIFLog
		_ = json.Unmarshal(sarifPartial, &partialLog)
		if partialLog.Runs[0].Invocations[0].ExecutionSuccessful {
			t.Errorf("partial SARIF run invocation executionSuccessful must be false")
		}
	})

	// -------------------------------------------------------------------------
	// Contract 9: CI feedback
	// summary formatting, inline comments restricted to verified diff locations.
	// -------------------------------------------------------------------------
	t.Run("Contract 9: CI Feedback Formatting and Diff Scoping", func(t *testing.T) {
		ciResult := &ci.Result{
			ExitCode: 0,
			Findings: []report.Finding{
				{
					ID:       "f-inline-1",
					Title:    "Inline vuln in app.js",
					Severity: "HIGH",
					RuleID:   "FELIX-INLINE-1",
					EvidenceDetails: report.EvidenceDetails{
						Location: "app.js:10",
					},
				},
				{
					ID:       "f-url-endpoint",
					Title:    "Web endpoint exposure",
					Severity: "LOW",
					Endpoint: "https://example.com/api/v1/status",
				},
			},
		}

		ciConfig := &ci.Config{
			Provider:  ci.ProviderGitHub,
			TargetURL: "https://example.com",
			PRComment: true,
			PRInline:  true,
		}

		summary := ci.FormatPRSummary(ciResult, ciConfig, "")
		if !strings.Contains(summary, "FELIX Security Assessment Summary") {
			t.Errorf("summary missing expected header: %s", summary)
		}

		// Verify diff parser and location extraction
		diffText := "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -5,10 +10,12 @@\n+line 10 modified\n"
		validLines := ci.ParsePRDiff(diffText)
		if !validLines["app.js"][10] {
			t.Errorf("expected app.js line 10 to be recognized in PR diff")
		}

		path, line, ok := ci.ExtractSourceLocation(ciResult.Findings[0])
		if !ok || path != "app.js" || line != 10 {
			t.Errorf("expected app.js:10, got %s:%d (ok=%v)", path, line, ok)
		}

		// Web endpoint finding must NOT produce inline source code locations
		_, _, okWeb := ci.ExtractSourceLocation(ciResult.Findings[1])
		if okWeb {
			t.Errorf("web endpoint URL must NOT be treated as a source file location")
		}
	})

	// -------------------------------------------------------------------------
	// Contract 10: Retry/recovery idempotency and worker lease fencing
	// -------------------------------------------------------------------------
	t.Run("Contract 10: Retry Idempotency and Worker Lease Fencing", func(t *testing.T) {
		now := time.Now().UTC()
		workerID := "live-worker-p8-gate"
		leaseExp := now.Add(10 * time.Minute)

		activeExec := &assessment.AssessmentExecution{
			ID:               "exec-gate-live-worker",
			AssessmentID:     asm.ID,
			ClientID:         client.ID,
			InitiationSource: "manual",
			Status:           assessment.StatusRunning,
			StartedAt:        now.Add(-2 * time.Minute),
			WorkerID:         workerID,
			HeartbeatAt:      &now,
			LeaseExpiresAt:   &leaseExp,
		}
		_ = store.CreateExecution(activeExec)

		// Recovery sweep cannot steal ownership from active worker
		recSummary, err := store.RecoverExecutions(assessment.RecoveryOptions{
			Auth:          assessment.NewAdminAuthContext(),
			StaleDuration: 1 * time.Minute,
			MaxRetries:    3,
			WorkerID:      "recovery-sweeper",
		})
		if err != nil {
			t.Fatalf("RecoverExecutions failed: %v", err)
		}
		if recSummary.ExaminedCount != 0 || recSummary.RecoveredCount != 0 {
			t.Errorf("active worker execution was improperly recovered by sweeper!")
		}

		// Direct finalization by recovery sweeper returns ActionSkippedNoOwnership
		finRes, err := store.FinalizeAbandonedExecution(
			activeExec.ID,
			"recovery-sweeper",
			assessment.StatusInterrupted,
			"test attempt",
			assessment.NewAdminAuthContext(),
		)
		if err != nil {
			t.Fatalf("FinalizeAbandonedExecution error: %v", err)
		}
		if finRes.Action != assessment.ActionSkippedNoOwnership {
			t.Errorf("expected ActionSkippedNoOwnership for active leased run, got: %s", finRes.Action)
		}
	})

	// -------------------------------------------------------------------------
	// Contract 11: Provenance consistency
	// assessment ID, execution ID, config digest, policy digest, baseline ref, and artifacts refer to same execution.
	// -------------------------------------------------------------------------
	t.Run("Contract 11: Provenance Consistency", func(t *testing.T) {
		prov := provenance.CaptureStart(context.Background(), provenance.StartOptions{
			AssessmentID:    "asm-gate-consistency",
			ExecutionID:     "exec-gate-consistency",
			TargetIdentity:  "https://example.com",
			ApprovedTargets: []string{"https://example.com"},
			Config:          map[string]any{"concurrency": 4},
			BaselineRef:     "exec-gate-base-valid",
			EnabledEngines:  []string{"websec"},
		})

		prov.Finalize(provenance.FinalizeOptions{
			Status:          "COMPLETED",
			FailureCategory: "SUCCESS",
			ExitCode:        0,
			DurationMs:      1250,
			IsPartial:       false,
			Artifacts: []provenance.ArtifactProvenance{
				{Path: "report.json", Digest: "sha256:aaa111"},
				{Path: "felix.sarif", Digest: "sha256:bbb222"},
			},
		})

		if prov.AssessmentID != "asm-gate-consistency" || prov.ExecutionID != "exec-gate-consistency" {
			t.Errorf("provenance ID mismatch: %s / %s", prov.AssessmentID, prov.ExecutionID)
		}
		if prov.ConfigDigest == "" {
			t.Errorf("expected non-empty config digest in provenance")
		}
		if prov.BaselineRef != "exec-gate-base-valid" {
			t.Errorf("provenance baseline ref mismatch")
		}
		if len(prov.Artifacts) != 2 {
			t.Errorf("expected 2 artifact digests in provenance, got %d", len(prov.Artifacts))
		}
	})

	// -------------------------------------------------------------------------
	// Contract 12: Secret protection
	// credentials and tokens do not appear in persisted provenance, reports, or error output.
	// -------------------------------------------------------------------------
	t.Run("Contract 12: Secret Protection and Token Redaction", func(t *testing.T) {
		rawConfig := map[string]any{
			"target_url":    "https://example.com",
			"concurrency":   4,
			"api_token":     "ghp_SecretGitHubToken1234567890",
			"auth_header":   "Bearer my-super-secret-jwt-token",
			"database_url":  "postgres://user:supersecretpass@db.example.com/db",
			"client_secret": "client_secret_xyz_987654",
		}

		digest, sanitizedMap, err := provenance.ComputeConfigDigest(rawConfig)
		if err != nil {
			t.Fatalf("ComputeConfigDigest failed: %v", err)
		}
		if digest == "" {
			t.Fatal("expected non-empty deterministic digest")
		}

		// Ensure sensitive keys are omitted from sanitized configuration
		for key := range sanitizedMap {
			if strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "header") || strings.Contains(key, "pass") {
				t.Fatalf("sensitive key %q leaked into sanitized config!", key)
			}
		}

		// Secret text redaction
		sensitiveLog := "Authentication failed with token ghp_SecretGitHubToken1234567890 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		redacted := secrets.RedactText(sensitiveLog)
		if strings.Contains(redacted, "ghp_SecretGitHubToken1234567890") {
			t.Errorf("raw token leaked through secrets.RedactText: %s", redacted)
		}
		if !strings.Contains(redacted, "[REDACTED") {
			t.Errorf("expected [REDACTED] tag in redacted text: %s", redacted)
		}
	})
}
