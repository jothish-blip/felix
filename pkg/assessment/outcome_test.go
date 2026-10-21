package assessment

import (
	"errors"
	"testing"

	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/report"
)

func TestDetermineOutcomeExitCode(t *testing.T) {
	tests := []struct {
		name         string
		status       AssessmentStatus
		runErr       error
		htmlReq      bool
		htmlGen      bool
		jsonReq      bool
		jsonGen      bool
		expectedCode int
	}{
		{
			name:         "clean completed assessment",
			status:       StatusCompleted,
			runErr:       nil,
			expectedCode: clierror.ExitSuccess, // 0
		},
		{
			name:         "completed with findings but no policy threshold configured",
			status:       StatusCompleted,
			runErr:       nil,
			expectedCode: clierror.ExitSuccess, // 0
		},
		{
			name:         "operational error on execution",
			status:       StatusCompleted,
			runErr:       errors.New("connection failed"),
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "failed execution status",
			status:       StatusFailed,
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "cancelled execution status",
			status:       StatusCancelled,
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "interrupted execution status",
			status:       StatusInterrupted,
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "completed with crawl errors (untrustworthy partial)",
			status:       StatusCompletedWithErrors,
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "html report requested and generated",
			status:       StatusCompleted,
			runErr:       nil,
			htmlReq:      true,
			htmlGen:      true,
			expectedCode: clierror.ExitSuccess, // 0
		},
		{
			name:         "html report requested but failed to generate",
			status:       StatusCompleted,
			runErr:       nil,
			htmlReq:      true,
			htmlGen:      false,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "json report requested but failed to generate",
			status:       StatusCompleted,
			runErr:       nil,
			jsonReq:      true,
			jsonGen:      false,
			expectedCode: clierror.ExitOperational, // 2
		},
		{
			name:         "unknown or unclassified status",
			status:       AssessmentStatus("UNKNOWN_STATE"),
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := DetermineOutcomeExitCode(tc.status, tc.runErr, tc.htmlReq, tc.htmlGen, tc.jsonReq, tc.jsonGen)
			if code != tc.expectedCode {
				t.Fatalf("expected code %d, got %d", tc.expectedCode, code)
			}
		})
	}
}

func TestExecutionResult_ClassifyOutcome(t *testing.T) {
	// Nil result returns operational
	var nilRes *ExecutionResult
	if code := nilRes.ClassifyOutcome(false, false); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational for nil ExecutionResult, got %d", code)
	}

	// Completed with report files
	res := &ExecutionResult{
		Execution: &AssessmentExecution{
			Status: StatusCompleted,
		},
		HTMLPath: "/reports/test.html",
		JSONPath: "/reports/test.json",
	}

	if code := res.ClassifyOutcome(true, true); code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %d", code)
	}

	// Completed but requested HTML missing
	resNoHTML := &ExecutionResult{
		Execution: &AssessmentExecution{
			Status: StatusCompleted,
		},
		HTMLPath: "",
	}
	if code := resNoHTML.ClassifyOutcome(true, false); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational when requested HTML was not generated, got %d", code)
	}
}

func TestExecutionResult_ClassifyOutcomeWithPolicy(t *testing.T) {
	zero := 0
	two := 2

	// Policy: MaxCritical = 0, MaxHigh = 2
	pol := &policy.ThresholdPolicy{
		Version:     "1.0",
		Name:        "ci-gate",
		MaxCritical: &zero,
		MaxHigh:     &two,
	}

	// 1. Without policy (nil): completed assessment with findings returns 0
	resWithFindings := &ExecutionResult{
		Execution: &AssessmentExecution{
			AssessmentID: "ASM-POL-01",
			Status:       StatusCompleted,
		},
		Report: &report.Report{
			CompletionStatus: "COMPLETED",
			Findings: []report.Finding{
				{
					ID:       "f1",
					Title:    "High Finding",
					Severity: "HIGH",
					Target:   "https://example.com/1",
				},
			},
		},
	}

	decNil, codeNil := resWithFindings.ClassifyOutcomeWithPolicy(nil, false, false)
	if decNil != nil {
		t.Errorf("expected nil decision when policy is nil")
	}
	if codeNil != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for completed run when no policy provided, got %d", codeNil)
	}

	// 2. With policy: 1 High finding (limit is 2), 0 Critical -> PASSED -> ExitSuccess (0)
	decPass, codePass := resWithFindings.ClassifyOutcomeWithPolicy(pol, false, false)
	if decPass == nil || !decPass.Passed {
		t.Fatalf("expected policy to pass for 1 High <= 2 allowed, got %+v", decPass)
	}
	if codePass != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for satisfied policy, got %d", codePass)
	}

	// 3. With policy: 3 High findings (limit is 2) -> VIOLATION -> ExitSecurityFail (1)
	resViolated := &ExecutionResult{
		Execution: &AssessmentExecution{
			AssessmentID: "ASM-POL-01",
			Status:       StatusCompleted,
		},
		Report: &report.Report{
			CompletionStatus: "COMPLETED",
			Findings: []report.Finding{
				{ID: "f1", Title: "H1", Severity: "HIGH", Target: "https://example.com/1", Endpoint: "/1"},
				{ID: "f2", Title: "H2", Severity: "HIGH", Target: "https://example.com/2", Endpoint: "/2"},
				{ID: "f3", Title: "H3", Severity: "HIGH", Target: "https://example.com/3", Endpoint: "/3"},
			},
		},
	}
	decFail, codeFail := resViolated.ClassifyOutcomeWithPolicy(pol, false, false)
	if decFail == nil || decFail.Passed {
		t.Fatalf("expected policy to fail for 3 High > 2 allowed, got %+v", decFail)
	}
	if codeFail != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for threshold violation, got %d", codeFail)
	}

	// 4. With policy: operational execution failure -> ExitOperational (2), NEVER 0 or 1!
	resFailed := &ExecutionResult{
		Execution: &AssessmentExecution{
			AssessmentID: "ASM-POL-01",
			Status:       StatusFailed,
		},
		Report: &report.Report{
			CompletionStatus: "FAILED",
			Findings:         []report.Finding{},
		},
		Error: errors.New("timeout reached"),
	}
	decOp, codeOp := resFailed.ClassifyOutcomeWithPolicy(pol, false, false)
	if decOp == nil || decOp.Reliable {
		t.Fatalf("expected decision to be unreliable for failed execution, got %+v", decOp)
	}
	if codeOp != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for failed execution, got %d", codeOp)
	}

	// 5. With policy: requested artifact write failure -> ExitOperational (2)
	resArtifactFail := &ExecutionResult{
		Execution: &AssessmentExecution{
			AssessmentID: "ASM-POL-01",
			Status:       StatusCompleted,
		},
		Report: &report.Report{
			CompletionStatus: "COMPLETED",
			Findings:         []report.Finding{},
		},
		HTMLPath: "", // requested but missing
	}
	_, codeArt := resArtifactFail.ClassifyOutcomeWithPolicy(pol, true, false)
	if codeArt != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) when requested report artifact failed, got %d", codeArt)
	}
}
