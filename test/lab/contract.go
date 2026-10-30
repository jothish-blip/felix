package lab

import (
	"time"
)

// TestStatus represents the outcome of a lab test case execution.
type TestStatus string

const (
	StatusPass      TestStatus = "PASS"
	StatusFail      TestStatus = "FAIL"
	StatusBlocked   TestStatus = "BLOCKED"
	StatusNotTested TestStatus = "NOT_TESTED"
)

// TestCaseContract encapsulates the complete specification, expected ground truth,
// actual execution evidence, and outcome classification for each test case.
type TestCaseContract struct {
	// Unique test ID (e.g. LAB-BOLA-001)
	TestID string `json:"test_id"`

	// Feature or command under test (e.g. "felix assessment bola")
	Feature string `json:"feature"`

	// Command line invocation executed
	Command string `json:"command"`

	// Target fixture and preconditions
	TargetFixture string   `json:"target_fixture"`
	Preconditions []string `json:"preconditions"`

	// Expected result based on independently verified ground truth
	GroundTruth      string `json:"ground_truth"`
	ExpectedFinding  string `json:"expected_finding,omitempty"`
	ExpectedSeverity string `json:"expected_severity,omitempty"`
	ExpectedExitCode int    `json:"expected_exit_code"`
	ExpectedSideEffects string `json:"expected_side_effects,omitempty"`

	// Actual result and evidence
	ActualResult          string     `json:"actual_result"`
	ActualExitCode        int        `json:"actual_exit_code"`
	DurationMs            int64      `json:"duration_ms"`
	Status                TestStatus `json:"status"`
	StdoutSnippet         string     `json:"stdout_snippet,omitempty"`
	StderrSnippet         string     `json:"stderr_snippet,omitempty"`
	Evidence              string     `json:"evidence,omitempty"`

	// Failure classification & regression reference
	FailureClassification string    `json:"failure_classification,omitempty"`
	RegressionRef          string    `json:"regression_ref,omitempty"`
	ExecutedAt            time.Time `json:"executed_at"`
}

// LabExecutionReport aggregates the full run of test cases in the local lab.
type LabExecutionReport struct {
	GeneratedAt time.Time          `json:"generated_at"`
	TotalCases  int                `json:"total_cases"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
	Blocked     int                `json:"blocked"`
	NotTested   int                `json:"not_tested"`
	Results     []TestCaseContract `json:"results"`
}
