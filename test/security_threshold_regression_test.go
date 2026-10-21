package test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"felix/pkg/assessment"
	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/report"
)

func TestPhase82_PolicyThreshold_EvaluationMatrix(t *testing.T) {
	// 1. Thresholds: Critical=0, High=2
	maxCrit := 0
	maxHigh := 2
	pol := &policy.ThresholdPolicy{
		Version:     "1.0",
		Name:        "Strict CI Gate",
		MaxCritical: &maxCrit,
		MaxHigh:     &maxHigh,
	}

	ctx := policy.EvaluationContext{
		AssessmentID: "asm-reg-1",
		TenantID:     "tenant-1",
		Status:       "COMPLETED",
		TargetScope:  []string{"https://example.com"},
	}

	// Case A: 1 High finding -> within threshold (High <= 2, Critical == 0)
	findingsA := []report.Finding{
		{
			ID:          "f-1",
			Severity:    report.SeverityHigh,
			Title:       "Weak TLS cipher suite",
			Target:      "https://example.com",
			Fingerprint: "fp-1",
		},
	}
	decA, err := policy.EvaluatePolicy(pol, findingsA, ctx)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if !decA.Passed || !decA.Reliable {
		t.Fatalf("expected pass with 1 high finding, got passed=%v reliable=%v", decA.Passed, decA.Reliable)
	}
	if decA.ExitCode() != clierror.ExitSuccess {
		t.Fatalf("expected exit code 0, got %d", decA.ExitCode())
	}

	// Case B: 1 Critical finding -> exceeds threshold (Critical > 0)
	findingsB := append(findingsA, report.Finding{
		ID:          "f-2",
		Severity:    report.SeverityCritical,
		Title:       "Unauthenticated RCE",
		Target:      "https://example.com",
		Fingerprint: "fp-2",
	})
	decB, err := policy.EvaluatePolicy(pol, findingsB, ctx)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if decB.Passed {
		t.Fatalf("expected policy failure for critical finding")
	}
	if !decB.Reliable {
		t.Fatalf("expected assessment to be reliable despite threshold violation")
	}
	if decB.ExitCode() != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code 1, got %d", decB.ExitCode())
	}
	if len(decB.Violations) != 1 || decB.Violations[0].Severity != "CRITICAL" {
		t.Fatalf("expected 1 CRITICAL violation, got %+v", decB.Violations)
	}

	// Case C: 3 High findings -> exceeds threshold (High > 2)
	findingsC := []report.Finding{
		{ID: "f-h1", Title: "High Vulnerability 1", Severity: report.SeverityHigh, Target: "https://example.com/api/v1/auth", Endpoint: "/api/v1/auth"},
		{ID: "f-h2", Title: "High Vulnerability 2", Severity: report.SeverityHigh, Target: "https://example.com/api/v1/users", Endpoint: "/api/v1/users"},
		{ID: "f-h3", Title: "High Vulnerability 3", Severity: report.SeverityHigh, Target: "https://example.com/api/v1/billing", Endpoint: "/api/v1/billing"},
	}
	decC, err := policy.EvaluatePolicy(pol, findingsC, ctx)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if decC.Passed {
		t.Fatalf("expected failure when observed High (3) > max (2)")
	}
	if decC.ExitCode() != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code 1, got %d", decC.ExitCode())
	}

	// Case D: Incomplete / Operational Failure -> Must NOT pass or mask failure
	ctxFailed := policy.EvaluationContext{
		AssessmentID:   "asm-reg-1",
		TenantID:       "tenant-1",
		Status:         "FAILED",
		ExecutionError: errors.New("Connection reset by peer"),
	}
	decD, err := policy.EvaluatePolicy(pol, []report.Finding{}, ctxFailed)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if decD.Passed {
		t.Fatalf("failed assessment must not pass policy evaluation")
	}
	if decD.Reliable {
		t.Fatalf("failed assessment must not be marked reliable")
	}
	if decD.ExitCode() != clierror.ExitOperational {
		t.Fatalf("expected exit code 2 for operational failure, got %d", decD.ExitCode())
	}
}

func TestPhase82_PolicyFileLoading_JSONAndYAML(t *testing.T) {
	tmpDir := t.TempDir()

	// YAML policy
	yamlContent := `
version: "1.0"
name: "Production Pipeline Gate"
description: "Zero critical and maximum one high finding allowed"
max_critical: 0
max_high: 1
max_medium: 5
`
	yamlPath := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write yaml: %v", err)
	}

	polY, err := policy.LoadPolicy(yamlPath)
	if err != nil {
		t.Fatalf("failed to load yaml policy: %v", err)
	}
	if polY.MaxCritical == nil || *polY.MaxCritical != 0 {
		t.Errorf("expected max_critical=0, got %v", polY.MaxCritical)
	}
	if polY.MaxHigh == nil || *polY.MaxHigh != 1 {
		t.Errorf("expected max_high=1, got %v", polY.MaxHigh)
	}
	if polY.MaxMedium == nil || *polY.MaxMedium != 5 {
		t.Errorf("expected max_medium=5, got %v", polY.MaxMedium)
	}

	// JSON policy
	jsonContent := `{
		"version": "1.0",
		"name": "JSON Gate",
		"max_critical": 0,
		"max_high": 0
	}`
	jsonPath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write json: %v", err)
	}

	polJ, err := policy.LoadPolicy(jsonPath)
	if err != nil {
		t.Fatalf("failed to load json policy: %v", err)
	}
	if polJ.MaxCritical == nil || *polJ.MaxCritical != 0 {
		t.Errorf("expected max_critical=0, got %v", polJ.MaxCritical)
	}
}

func TestPhase82_ExecutionResult_OutcomeIntegration(t *testing.T) {
	maxCrit := 0
	pol := &policy.ThresholdPolicy{
		Version:     "1.0",
		Name:        "Zero Critical Gate",
		MaxCritical: &maxCrit,
	}

	rep := &report.Report{
		CompletionStatus: "COMPLETED",
		Findings: []report.Finding{
			{
				ID:          "f-crit-1",
				Severity:    report.SeverityCritical,
				Title:       "SQL Injection",
				Fingerprint: "fp-sqli",
				Target:      "https://example.com/login",
			},
		},
	}

	res := &assessment.ExecutionResult{
		Execution: &assessment.AssessmentExecution{
			AssessmentID: "asm-outcome-82",
			Status:       assessment.StatusCompleted,
		},
		Report: rep,
	}

	dec, code := res.ClassifyOutcomeWithPolicy(pol, false, false)
	if dec == nil {
		t.Fatalf("expected non-nil policy decision")
	}
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code 1 for critical threshold violation, got %d", code)
	}
	if dec.Passed {
		t.Fatalf("expected policy evaluation to fail")
	}

	// Verify metadata attachment
	evalMeta, ok := rep.Metadata["policy_evaluation"]
	if !ok {
		t.Fatalf("expected policy_evaluation in report metadata")
	}
	metaBytes, _ := json.Marshal(evalMeta)
	if len(metaBytes) == 0 {
		t.Fatalf("expected valid serialized policy evaluation in metadata")
	}
}

func TestPhase82_InterruptedAssessment_ReturnsOperationalExitCode(t *testing.T) {
	maxCrit := 0
	pol := &policy.ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &maxCrit,
	}

	// An interrupted or timed out assessment with NO findings
	res := &assessment.ExecutionResult{
		Execution: &assessment.AssessmentExecution{
			AssessmentID: "asm-interrupted",
			Status:       assessment.StatusInterrupted,
		},
		Error: context.DeadlineExceeded,
		Report: &report.Report{
			CompletionStatus: "INTERRUPTED",
			Findings:         []report.Finding{},
		},
	}

	dec, code := res.ClassifyOutcomeWithPolicy(pol, false, false)
	if dec.Passed {
		t.Fatalf("interrupted assessment must not pass policy evaluation")
	}
	if dec.Reliable {
		t.Fatalf("interrupted assessment must not be marked reliable")
	}
	if code != clierror.ExitOperational {
		t.Fatalf("expected exit code 2 (operational), got %d", code)
	}
}
