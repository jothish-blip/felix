package clierror

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodeFor_NilReturnsSuccess(t *testing.T) {
	code := CodeFor(nil)
	if code != ExitSuccess {
		t.Fatalf("expected ExitSuccess (%d) for nil error, got %d", ExitSuccess, code)
	}
}

func TestCodeFor_OperationalError(t *testing.T) {
	err := Operational("database connection refused")
	if code := CodeFor(err); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d), got %d", ExitOperational, code)
	}

	if err.Error() != "database connection refused" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestCodeFor_WrappedOperationalError(t *testing.T) {
	inner := errors.New("underlying socket timeout")
	wrapped := WrapOperational(inner, "API gateway unreachable")
	if code := CodeFor(wrapped); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d), got %d", ExitOperational, code)
	}

	if !errors.Is(wrapped, inner) {
		t.Fatalf("expected wrapped error to match inner via errors.Is")
	}

	// Deeply wrapped with standard fmt.Errorf
	deep := fmt.Errorf("outer context: %w", wrapped)
	if code := CodeFor(deep); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d) for deeply wrapped error, got %d", ExitOperational, code)
	}
}

func TestCodeFor_SecurityFailureError(t *testing.T) {
	err := SecurityFailure("security refusal: target not authorized")
	if code := CodeFor(err); code != ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (%d), got %d", ExitSecurityFail, code)
	}

	// Wrapped security failure
	inner := errors.New("unauthorized target")
	wrapped := WrapSecurityFailure(inner, "refused by security policy")
	if code := CodeFor(wrapped); code != ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (%d), got %d", ExitSecurityFail, code)
	}

	deep := fmt.Errorf("execution halted: %w", wrapped)
	if code := CodeFor(deep); code != ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (%d) for deeply wrapped security failure, got %d", ExitSecurityFail, code)
	}
}

func TestCodeFor_UsageError(t *testing.T) {
	err := Usage("unknown flag: --foo")
	if code := CodeFor(err); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d), got %d", ExitOperational, code)
	}

	wrapped := WrapUsage(errors.New("invalid int"), "bad concurrency value")
	if code := CodeFor(wrapped); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d), got %d", ExitOperational, code)
	}
}

func TestCodeFor_UnclassifiedErrorDefaultsToOperational(t *testing.T) {
	err := errors.New("some unexpected internal error")
	if code := CodeFor(err); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d) for unclassified error, got %d", ExitOperational, code)
	}
}

func TestCodeFor_CustomExitError(t *testing.T) {
	custom := New(ExitSecurityFail, "custom security failure")
	if code := CodeFor(custom); code != ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (%d), got %d", ExitSecurityFail, code)
	}

	wrap := Wrap(ExitOperational, custom, "escalated to operational")
	if code := CodeFor(wrap); code != ExitOperational {
		t.Fatalf("expected ExitOperational (%d), got %d", ExitOperational, code)
	}
}

func TestErrorsIs_ClassificationAndWrapping(t *testing.T) {
	// 1. Security failure matching
	secErr := SecurityFailure("threshold violated: 2 critical")
	deepSec := fmt.Errorf("outer layer: %w", fmt.Errorf("middle layer: %w", secErr))
	if !errors.Is(deepSec, ErrSecurityViolation) {
		t.Errorf("expected deeply wrapped SecurityFailureError to match ErrSecurityViolation")
	}

	// 2. Operational error matching
	opErr := Operational("engine failed to start")
	deepOp := fmt.Errorf("step failed: %w", fmt.Errorf("init error: %w", opErr))
	if !errors.Is(deepOp, ErrToolFailure) {
		t.Errorf("expected deeply wrapped OperationalError to match ErrToolFailure")
	}

	// 3. Incomplete assessment matching
	incErr := Incomplete("scan cancelled by user")
	deepInc := fmt.Errorf("pipeline aborted: %w", fmt.Errorf("runner signal: %w", incErr))
	if !errors.Is(deepInc, ErrIncomplete) {
		t.Errorf("expected deeply wrapped IncompleteAssessmentError to match ErrIncomplete")
	}

	// 4. Classification struct as error with Is() matching
	clsSec := Classification{Category: CategorySecurityViolation, Code: ExitSecurityFail}
	if !errors.Is(clsSec, ErrSecurityViolation) {
		t.Errorf("expected Classification with CategorySecurityViolation to match ErrSecurityViolation")
	}
	if errors.Is(clsSec, ErrToolFailure) {
		t.Errorf("Classification with CategorySecurityViolation must not match ErrToolFailure")
	}

	clsTool := Classification{Category: CategoryToolFailure, Code: ExitOperational}
	if !errors.Is(clsTool, ErrToolFailure) {
		t.Errorf("expected Classification with CategoryToolFailure to match ErrToolFailure")
	}

	clsInc := Classification{Category: CategoryIncomplete, Code: ExitOperational}
	if !errors.Is(clsInc, ErrIncomplete) {
		t.Errorf("expected Classification with CategoryIncomplete to match ErrIncomplete")
	}
}

func TestClassifyAssessment_Matrix(t *testing.T) {
	cases := []struct {
		name                 string
		status               string
		execErr              error
		hasSecurityViolation bool
		policyErr            error
		secondaryErrs        []error
		expectedCategory     FailureCategory
		expectedExit         int
	}{
		{
			name:                 "Assessment completes; policy passes",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategorySuccess,
			expectedExit:         ExitSuccess,
		},
		{
			name:                 "Assessment completes; policy threshold is violated",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: true,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategorySecurityViolation,
			expectedExit:         ExitSecurityFail,
		},
		{
			name:                 "Invalid configuration",
			status:               "",
			execErr:              errors.New("invalid target url"),
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategoryToolFailure,
			expectedExit:         ExitOperational,
		},
		{
			name:                 "Required engine initialization fails",
			status:               "",
			execErr:              errors.New("failed to initialize crawler engine"),
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategoryToolFailure,
			expectedExit:         ExitOperational,
		},
		{
			name:                 "Required scanner operation fails before a valid result exists",
			status:               "FAILED",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategoryToolFailure,
			expectedExit:         ExitOperational,
		},
		{
			name:                 "Required assessment stage fails after partial findings (completed with errors)",
			status:               "COMPLETED_WITH_ERRORS",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategoryIncomplete,
			expectedExit:         ExitOperational,
		},
		{
			name:                 "Cancellation or timeout prevents required completion",
			status:               "CANCELLED",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategoryIncomplete,
			expectedExit:         ExitOperational,
		},
		{
			name:                 "Security violation is established, then reporting fails",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: true,
			policyErr:            nil,
			secondaryErrs:        []error{errors.New("disk full: failed writing report.html")},
			expectedCategory:     CategorySecurityViolation,
			expectedExit:         ExitSecurityFail, // Preserves Exit 1!
		},
		{
			name:                 "Clean assessment; feedback fails under warn (warn error not passed as secondary)",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        nil,
			expectedCategory:     CategorySuccess,
			expectedExit:         ExitSuccess,
		},
		{
			name:                 "Clean assessment; feedback fails under fail",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        []error{errors.New("mandatory PR comment failed: HTTP 403")},
			expectedCategory:     CategoryToolFailure,
			expectedExit:         ExitOperational, // Elevated to Exit 2!
		},
		{
			name:                 "Security violation; feedback fails under fail",
			status:               "COMPLETED",
			execErr:              nil,
			hasSecurityViolation: true,
			policyErr:            nil,
			secondaryErrs:        []error{errors.New("mandatory PR review failed: HTTP 429")},
			expectedCategory:     CategorySecurityViolation,
			expectedExit:         ExitSecurityFail, // Preserves Exit 1!
		},
		{
			name:                 "Assessment fails operationally and feedback also fails",
			status:               "FAILED",
			execErr:              errors.New("network timeout"),
			hasSecurityViolation: false,
			policyErr:            nil,
			secondaryErrs:        []error{errors.New("feedback also failed")},
			expectedCategory:     CategoryToolFailure,
			expectedExit:         ExitOperational,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls := ClassifyAssessment(tc.status, tc.execErr, tc.hasSecurityViolation, tc.policyErr, tc.secondaryErrs...)
			if cls.Category != tc.expectedCategory {
				t.Errorf("expected category %s, got %s", tc.expectedCategory, cls.Category)
			}
			if cls.ExitCode() != tc.expectedExit {
				t.Errorf("expected exit code %d, got %d", tc.expectedExit, cls.ExitCode())
			}

			// Verify secondary errors are retained when reporting or feedback fails
			if len(tc.secondaryErrs) > 0 {
				if len(cls.SecondaryErrors) != len(tc.secondaryErrs) {
					t.Errorf("expected %d secondary errors, got %d", len(tc.secondaryErrs), len(cls.SecondaryErrors))
				}
			}
		})
	}
}
