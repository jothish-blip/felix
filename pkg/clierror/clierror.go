package clierror

import (
	"errors"
	"fmt"
	"strings"
)

// Standard CLI Exit Codes for FELIX (Phase 8.1 Contract)
const (
	// ExitSuccess (0): Command completed successfully; no security-policy failure was established.
	ExitSuccess = 0

	// ExitSecurityFail (1): Assessment completed sufficiently to establish a security failure
	// under the existing command's security-result semantics.
	ExitSecurityFail = 1

	// ExitOperational (2): Operational or execution error: invalid arguments, configuration problems,
	// authentication/setup failure, failed assessment, interrupted/cancelled, or inability to produce a trustworthy result.
	ExitOperational = 2
)

// FailureCategory represents the semantic classification of a CLI or assessment outcome.
type FailureCategory string

const (
	// CategorySuccess indicates that the assessment and required evaluations completed
	// successfully with zero security-policy violations established. (Exit 0)
	CategorySuccess FailureCategory = "SUCCESS"

	// CategorySecurityViolation indicates that the assessment completed sufficiently
	// to evaluate security posture and established a security-policy or threshold violation. (Exit 1)
	CategorySecurityViolation FailureCategory = "SECURITY_VIOLATION"

	// CategoryToolFailure indicates that FELIX encountered an operational, configuration,
	// engine, scanner, or network failure preventing trustworthy completion. (Exit 2)
	CategoryToolFailure FailureCategory = "TOOL_FAILURE"

	// CategoryIncomplete indicates that the assessment was partial, cancelled, timed out,
	// or had crawl defects preventing a trustworthy complete result. (Exit 2)
	CategoryIncomplete FailureCategory = "INCOMPLETE"
)

// ExitCode maps the failure category directly to the standard FELIX exit code (0, 1, or 2).
func (c FailureCategory) ExitCode() int {
	switch c {
	case CategorySuccess:
		return ExitSuccess
	case CategorySecurityViolation:
		return ExitSecurityFail
	case CategoryToolFailure, CategoryIncomplete:
		return ExitOperational
	default:
		return ExitOperational
	}
}

// Sentinel / target errors for errors.Is matching.
var (
	ErrSecurityViolation = &SecurityFailureError{Message: "security policy threshold violation"}
	ErrToolFailure       = &OperationalError{Message: "tool or operational failure"}
	ErrIncomplete        = &IncompleteAssessmentError{Message: "incomplete or partial assessment"}
)

// ExitCoder is implemented by types that have an explicit CLI process exit code.
type ExitCoder interface {
	ExitCode() int
}

// ExitError is an error that carries an explicit process exit code and message/cause.
type ExitError struct {
	Code    int
	Message string
	Err     error
}

func (e *ExitError) Error() string {
	if e.Message != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %v", e.Message, e.Err)
		}
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

func (e *ExitError) ExitCode() int {
	return e.Code
}

// OperationalError indicates an operational or runtime defect (Code 2).
type OperationalError struct {
	Message string
	Err     error
}

func (e *OperationalError) Error() string {
	if e.Message != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %v", e.Message, e.Err)
		}
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "operational error"
}

func (e *OperationalError) Unwrap() error {
	return e.Err
}

func (e *OperationalError) ExitCode() int {
	return ExitOperational
}

func (e *OperationalError) Is(target error) bool {
	if target == nil {
		return false
	}
	if target == ErrToolFailure {
		return true
	}
	_, ok := target.(*OperationalError)
	return ok
}

// IncompleteAssessmentError indicates an incomplete, partial, cancelled, or timed-out assessment (Code 2).
type IncompleteAssessmentError struct {
	Message string
	Err     error
}

func (e *IncompleteAssessmentError) Error() string {
	if e.Message != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %v", e.Message, e.Err)
		}
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "incomplete assessment"
}

func (e *IncompleteAssessmentError) Unwrap() error {
	return e.Err
}

func (e *IncompleteAssessmentError) ExitCode() int {
	return ExitOperational
}

func (e *IncompleteAssessmentError) Is(target error) bool {
	if target == nil {
		return false
	}
	if target == ErrIncomplete {
		return true
	}
	_, ok := target.(*IncompleteAssessmentError)
	return ok
}

// SecurityFailureError indicates an established security-policy violation or security failure (Code 1).
type SecurityFailureError struct {
	Message string
	Err     error
}

func (e *SecurityFailureError) Error() string {
	if e.Message != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %v", e.Message, e.Err)
		}
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "security policy failure"
}

func (e *SecurityFailureError) Unwrap() error {
	return e.Err
}

func (e *SecurityFailureError) ExitCode() int {
	return ExitSecurityFail
}

func (e *SecurityFailureError) Is(target error) bool {
	if target == nil {
		return false
	}
	if target == ErrSecurityViolation {
		return true
	}
	_, ok := target.(*SecurityFailureError)
	return ok
}

// UsageError indicates an argument parsing or command usage defect (Code 2).
type UsageError struct {
	Message string
	Err     error
}

func (e *UsageError) Error() string {
	if e.Message != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %v", e.Message, e.Err)
		}
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "usage error"
}

func (e *UsageError) Unwrap() error {
	return e.Err
}

func (e *UsageError) ExitCode() int {
	return ExitOperational
}

func (e *UsageError) Is(target error) bool {
	if target == nil {
		return false
	}
	_, ok := target.(*UsageError)
	return ok
}

// Classification encapsulates the definitive failure or success classification of an operation.
type Classification struct {
	Category         FailureCategory `json:"category"`
	Code             int             `json:"exit_code"`
	AssessmentStatus string          `json:"assessment_status,omitempty"`
	PolicyStatus     string          `json:"policy_status,omitempty"`
	PrimaryError     error           `json:"-"`
	SecondaryErrors  []error         `json:"-"`
}

func (c Classification) Error() string {
	if c.PrimaryError != nil {
		return c.PrimaryError.Error()
	}
	return fmt.Sprintf("[%s] exit code %d", c.Category, c.Code)
}

func (c Classification) Unwrap() error {
	return c.PrimaryError
}

// ExitCode satisfies the ExitCoder interface.
func (c Classification) ExitCode() int {
	return c.Code
}

func (c Classification) ExitCodeValue() int {
	return c.Code
}

func (c Classification) Is(target error) bool {
	switch target {
	case ErrSecurityViolation:
		return c.Category == CategorySecurityViolation
	case ErrToolFailure:
		return c.Category == CategoryToolFailure
	case ErrIncomplete:
		return c.Category == CategoryIncomplete
	default:
		return false
	}
}

func (c Classification) IsSuccess() bool {
	return c.Category == CategorySuccess
}

func (c Classification) IsSecurityViolation() bool {
	return c.Category == CategorySecurityViolation
}

func (c Classification) IsToolFailure() bool {
	return c.Category == CategoryToolFailure
}

func (c Classification) IsIncomplete() bool {
	return c.Category == CategoryIncomplete
}

// Incomplete creates an IncompleteAssessmentError (Code 2).
func Incomplete(format string, args ...any) *IncompleteAssessmentError {
	return &IncompleteAssessmentError{
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapIncomplete wraps an existing error as an IncompleteAssessmentError (Code 2).
func WrapIncomplete(err error, format string, args ...any) *IncompleteAssessmentError {
	return &IncompleteAssessmentError{
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// ClassifyAssessment determines the definitive failure category and exit code by applying established precedence:
// 1. If execution encountered an operational error, engine failure, or wasn't completed:
//    -> CategoryToolFailure / CategoryIncomplete (Exit 2). Findings discovered so far are preserved, but assessment cannot pass.
// 2. If a security policy threshold or baseline violation is established:
//    -> CategorySecurityViolation (Exit 1). Secondary operational errors (e.g. reporting, feedback) do NOT mask the violation.
// 3. If assessment completed cleanly with no security violations:
//    -> If a secondary operational error occurred (report write failed, mandatory feedback failed):
//       -> CategoryToolFailure (Exit 2).
//    -> Otherwise:
//       -> CategorySuccess (Exit 0).
func ClassifyAssessment(status string, execErr error, hasSecurityViolation bool, policyErr error, secondaryErrs ...error) Classification {
	normStatus := strings.ToUpper(strings.TrimSpace(status))

	// 1. If execution encountered a fatal error or wasn't started
	if execErr != nil {
		return Classification{
			Category:         CategoryToolFailure,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     execErr,
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	}

	// 2. If status represents an incomplete, interrupted, cancelled, or partial crawl execution
	switch normStatus {
	case "COMPLETED_WITH_ERRORS", "PARTIAL", "INSUFFICIENT_COVERAGE", "INCOMPLETE":
		incErr := fmt.Errorf("assessment completed with operational errors; coverage is partial or incomplete")
		return Classification{
			Category:         CategoryIncomplete,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     incErr,
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	case "CANCELLED", "INTERRUPTED":
		incErr := fmt.Errorf("assessment was cancelled or interrupted")
		return Classification{
			Category:         CategoryIncomplete,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     incErr,
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	case "FAILED", "BLOCKED":
		failErr := fmt.Errorf("assessment execution failed or was blocked")
		return Classification{
			Category:         CategoryToolFailure,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     failErr,
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	case "COMPLETED":
		// Execution completed successfully
	default:
		// Unknown or empty status defaults safely to tool failure
		failErr := fmt.Errorf("assessment status is indeterminate: %q", status)
		return Classification{
			Category:         CategoryToolFailure,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     failErr,
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	}

	// 3. Status is COMPLETED. Check policy evaluation error
	if policyErr != nil {
		return Classification{
			Category:         CategoryToolFailure,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "ERROR",
			PrimaryError:     fmt.Errorf("policy evaluation error: %w", policyErr),
			SecondaryErrors:  filterNilErrors(secondaryErrs),
		}
	}

	validSecondary := filterNilErrors(secondaryErrs)

	// 4. If a security policy violation was established:
	// PRECEDENCE RULE: Confirmed security policy violations MUST NOT be masked by secondary operational failures
	// (such as report writing failure, cleanup error, or PR feedback failure).
	if hasSecurityViolation {
		var primErr error = &SecurityFailureError{Message: "security policy threshold violation established"}
		return Classification{
			Category:         CategorySecurityViolation,
			Code:             ExitSecurityFail,
			AssessmentStatus: normStatus,
			PolicyStatus:     "FAIL",
			PrimaryError:     primErr,
			SecondaryErrors:  validSecondary,
		}
	}

	// 5. No security violation established. Check if any secondary operational errors occurred
	// (e.g. requested report write failed, or mandatory PR feedback failed under "fail" policy).
	if len(validSecondary) > 0 {
		return Classification{
			Category:         CategoryToolFailure,
			Code:             ExitOperational,
			AssessmentStatus: normStatus,
			PolicyStatus:     "PASS",
			PrimaryError:     validSecondary[0],
			SecondaryErrors:  validSecondary,
		}
	}

	// 6. Assessment completed, 0 policy violations, 0 operational errors -> Success (Exit 0)
	return Classification{
		Category:         CategorySuccess,
		Code:             ExitSuccess,
		AssessmentStatus: normStatus,
		PolicyStatus:     "PASS",
		PrimaryError:     nil,
		SecondaryErrors:  nil,
	}
}

func filterNilErrors(errs []error) []error {
	var result []error
	for _, e := range errs {
		if e != nil {
			result = append(result, e)
		}
	}
	return result
}

// New creates an ExitError with the given exit code and formatted message.
func New(code int, format string, args ...any) *ExitError {
	return &ExitError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// Wrap wraps an existing error with an explicit exit code and message.
func Wrap(code int, err error, message string) *ExitError {
	return &ExitError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Operational creates an OperationalError (Code 2).
func Operational(format string, args ...any) *OperationalError {
	return &OperationalError{
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapOperational wraps an existing error as an OperationalError (Code 2).
func WrapOperational(err error, format string, args ...any) *OperationalError {
	return &OperationalError{
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// SecurityFailure creates a SecurityFailureError (Code 1).
func SecurityFailure(format string, args ...any) *SecurityFailureError {
	return &SecurityFailureError{
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapSecurityFailure wraps an existing error as a SecurityFailureError (Code 1).
func WrapSecurityFailure(err error, format string, args ...any) *SecurityFailureError {
	return &SecurityFailureError{
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// Usage creates a UsageError (Code 2).
func Usage(format string, args ...any) *UsageError {
	return &UsageError{
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapUsage wraps an existing error as a UsageError (Code 2).
func WrapUsage(err error, format string, args ...any) *UsageError {
	return &UsageError{
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// CodeFor maps any error to an exit code (0, 1, or 2).
// - nil -> ExitSuccess (0)
// - If err (or any unwrapped error in the chain) implements ExitCoder -> ExitCode()
// - Any other non-nil error -> ExitOperational (2) as the safe default for unclassified failures.
func CodeFor(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var ec ExitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return ExitOperational
}
