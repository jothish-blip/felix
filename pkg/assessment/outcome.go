package assessment

import (
	"fmt"

	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/report"
)

// DetermineOutcomeExitCode maps an assessment execution outcome to the CI/CD-safe exit code contract:
// - ExitSuccess (0): Assessment completed successfully and no security failure was established.
// - ExitSecurityFail (1): Assessment completed and established a security failure (under existing command semantics).
// - ExitOperational (2): Assessment failed, cancelled, interrupted, completed with errors (partial/untrustworthy),
//   or requested report generation failed, or runtime error occurred.
func DetermineOutcomeExitCode(status AssessmentStatus, runErr error, htmlRequested, htmlGenerated, jsonRequested, jsonGenerated bool) int {
	return DetermineOutcomeExitCodeWithArtifacts(status, runErr, htmlRequested, htmlGenerated, jsonRequested, jsonGenerated, false, false)
}

// DetermineOutcomeExitCodeWithArtifacts evaluates outcome including SARIF report artifact status.
func DetermineOutcomeExitCodeWithArtifacts(status AssessmentStatus, runErr error, htmlRequested, htmlGenerated, jsonRequested, jsonGenerated, sarifRequested, sarifGenerated bool) int {
	var secErrs []error
	if htmlRequested && !htmlGenerated {
		secErrs = append(secErrs, fmt.Errorf("requested HTML report failed to generate"))
	}
	if jsonRequested && !jsonGenerated {
		secErrs = append(secErrs, fmt.Errorf("requested JSON report failed to generate"))
	}
	if sarifRequested && !sarifGenerated {
		secErrs = append(secErrs, fmt.Errorf("requested SARIF report failed to generate"))
	}
	cls := clierror.ClassifyAssessment(string(status), runErr, false, nil, secErrs...)
	return cls.ExitCode()
}

// ClassifyOutcome returns the CI/CD-safe exit code for the ExecutionResult.
func (r *ExecutionResult) ClassifyOutcome(htmlRequested, jsonRequested bool) int {
	return r.ClassifyOutcomeWithArtifacts(htmlRequested, jsonRequested, false)
}

// ClassifyOutcomeWithArtifacts returns the CI/CD-safe exit code considering HTML, JSON, and SARIF artifacts.
func (r *ExecutionResult) ClassifyOutcomeWithArtifacts(htmlRequested, jsonRequested, sarifRequested bool) int {
	if r == nil || r.Execution == nil {
		return clierror.ExitOperational
	}
	htmlGenerated := r.HTMLPath != ""
	jsonGenerated := r.JSONPath != ""
	sarifGenerated := r.SARIFPath != ""
	return DetermineOutcomeExitCodeWithArtifacts(r.Execution.Status, r.Error, htmlRequested, htmlGenerated, jsonRequested, jsonGenerated, sarifRequested, sarifGenerated)
}

// EvaluatePolicy evaluates a security threshold policy against the completed execution result.
func (r *ExecutionResult) EvaluatePolicy(pol *policy.ThresholdPolicy) (*policy.EvaluationDecision, error) {
	if r == nil || r.Execution == nil {
		return nil, fmt.Errorf("cannot evaluate policy on nil execution result")
	}
	if pol == nil {
		return nil, fmt.Errorf("cannot evaluate nil security threshold policy")
	}

	ctx := policy.EvaluationContext{
		AssessmentID:       r.Execution.AssessmentID,
		Status:             string(r.Execution.Status),
		ExecutionError:     r.Error,
		BaselineComparison: r.ChangeSummary,
	}

	var findings []report.Finding
	if r.Report != nil {
		findings = r.Report.Findings
	}

	decision, err := policy.EvaluatePolicy(pol, findings, ctx)
	if err != nil {
		return decision, err
	}

	if r.Report != nil {
		if r.Report.Metadata == nil {
			r.Report.Metadata = make(map[string]any)
		}
		r.Report.Metadata["policy_evaluation"] = decision
	}

	return decision, nil
}

// ClassifyOutcomeWithPolicy returns the evaluation decision and corresponding CI/CD exit code.
// If pol is nil, it falls back directly to ClassifyOutcome (preserving existing behavior).
// If pol is provided:
// - Operational failures return ExitOperational (2).
// - Policy threshold violations return ExitSecurityFail (1).
// - Completed assessments satisfying all thresholds return ExitSuccess (0).
func (r *ExecutionResult) ClassifyOutcomeWithPolicy(pol *policy.ThresholdPolicy, htmlRequested, jsonRequested bool) (*policy.EvaluationDecision, int) {
	return r.ClassifyOutcomeWithPolicyAndArtifacts(pol, htmlRequested, jsonRequested, false)
}

// ClassifyOutcomeWithPolicyAndArtifacts evaluates policy and checks that all requested artifacts (HTML, JSON, SARIF) succeeded.
// Follows the Phase 8.7 failure classification precedence:
// 1. If execution was cancelled, timed out, partial, or failed -> Incomplete/Tool failure (Exit 2).
// 2. If a security policy violation is established -> Security Violation (Exit 1). Secondary artifact write errors do NOT mask the violation.
// 3. If policy passed cleanly, but requested artifacts failed -> Tool failure (Exit 2).
// 4. If assessment and artifacts passed cleanly -> Success (Exit 0).
func (r *ExecutionResult) ClassifyOutcomeWithPolicyAndArtifacts(pol *policy.ThresholdPolicy, htmlRequested, jsonRequested, sarifRequested bool) (*policy.EvaluationDecision, int) {
	if r == nil || r.Execution == nil {
		cls := clierror.Classification{
			Category: clierror.CategoryToolFailure,
			Code:     clierror.ExitOperational,
		}
		if r != nil {
			r.Classification = cls
		}
		return nil, clierror.ExitOperational
	}

	var secErrs []error
	if htmlRequested && r.HTMLPath == "" {
		secErrs = append(secErrs, fmt.Errorf("requested HTML report failed to generate"))
	}
	if jsonRequested && r.JSONPath == "" {
		secErrs = append(secErrs, fmt.Errorf("requested JSON report failed to generate"))
	}
	if sarifRequested && r.SARIFPath == "" {
		secErrs = append(secErrs, fmt.Errorf("requested SARIF report failed to generate"))
	}

	if pol == nil {
		cls := clierror.ClassifyAssessment(string(r.Execution.Status), r.Error, false, nil, secErrs...)
		r.Classification = cls
		if r.Provenance != nil {
			r.Provenance.FailureCategory = string(cls.Category)
			r.Provenance.ExitCode = cls.ExitCode()
			r.Provenance.PolicyStatus = "NONE"
		}
		return nil, cls.ExitCode()
	}

	decision, polErr := r.EvaluatePolicy(pol)
	hasViolation := decision != nil && !decision.Passed

	cls := clierror.ClassifyAssessment(string(r.Execution.Status), r.Error, hasViolation, polErr, secErrs...)
	r.Classification = cls
	if r.Provenance != nil {
		r.Provenance.FailureCategory = string(cls.Category)
		r.Provenance.ExitCode = cls.ExitCode()
		if hasViolation {
			r.Provenance.PolicyStatus = "FAIL"
		} else if decision != nil && decision.Passed {
			r.Provenance.PolicyStatus = "PASS"
		} else {
			r.Provenance.PolicyStatus = "ERROR"
		}
	}

	return decision, cls.ExitCode()
}
