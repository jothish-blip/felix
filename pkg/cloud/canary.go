package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CanaryGuardrailChecker evaluates all 8 mandatory conditions required before canary write execution.
type CanaryGuardrailChecker struct {
	AllowWriteVerification bool
	ScopeValidator         func(string) bool
	ExclusionValidator     func(string) bool
}

// CanaryEvaluationResult contains the decision whether canary write is permitted.
type CanaryEvaluationResult struct {
	Allowed bool
	Reason  string
}

// EvaluateConditions verifies all 8 mandatory write guardrails.
func (c *CanaryGuardrailChecker) EvaluateConditions(
	target string,
	tech ServiceTechnology,
	canary CanaryConfig,
	identityMinPrivilege bool,
) CanaryEvaluationResult {
	// Condition 1: Global/User explicit opt-in
	if !c.AllowWriteVerification || !canary.Enabled {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "write verification disabled by default; requires explicit opt-in",
		}
	}

	// Condition 2: Explicit run configuration authorization
	if !canary.ExplicitlyAuthorized {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "run configuration does not record explicit write authorization",
		}
	}

	// Condition 3: Target and resource in-scope and not excluded
	if c.ExclusionValidator != nil && c.ExclusionValidator(target) {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "target matches active exclusion rule",
		}
	}
	if c.ScopeValidator != nil && !c.ScopeValidator(target) {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "target is outside authorized assessment scope",
		}
	}

	// Condition 4: Explicit test resource configured (never empty or arbitrary production path)
	cleanRes := strings.TrimSpace(canary.TargetResource)
	if cleanRes == "" || cleanRes == "/" || cleanRes == "*" {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "test resource identifier is empty or targets root/wildcard path",
		}
	}

	// Condition 5: Provider supports a safe, isolated canary operation
	if !IsCanarySupported(tech) {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("provider %s does not support isolated, non-destructive canary writes", tech),
		}
	}

	// Condition 6: No-overwrite guarantee
	if !canary.PreventOverwriteCheck {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "no-overwrite guarantee is not enabled",
		}
	}

	// Condition 7: Defined non-destructive cleanup
	if !canary.AllowCleanup {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "safe cleanup behavior is not verified or permitted",
		}
	}

	// Condition 8: Least-privilege identity confirmed
	if !identityMinPrivilege {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "identity is not verified as least-privilege for canary operation",
		}
	}

	return CanaryEvaluationResult{
		Allowed: true,
		Reason:  "all 8 write verification guardrails satisfied",
	}
}

// IsCanarySupported returns whether the technology safely supports isolated canary writes in FELIX.
func IsCanarySupported(tech ServiceTechnology) bool {
	switch tech {
	case TechRedis: // SET test_canary_key with NX (not exists)
		return true
	case TechAWSS3, TechMinIO: // PUT dedicated test object under /felix-canary/ with If-None-Match
		return true
	default:
		// Databases with production schema or complex state default to unsupported canary writes
		return false
	}
}

// CanaryOperation defines the execution lifecycle for an isolated canary test.
type CanaryOperation interface {
	PreCheck(ctx context.Context) error   // Check if resource already exists to prevent overwrite
	Execute(ctx context.Context) error    // Execute isolated write
	Verify(ctx context.Context) error     // Confirm write succeeded
	Cleanup(ctx context.Context) error    // Non-destructive cleanup of written canary
}

// ExecuteCanaryLifecycle executes the canary with pre-check and guaranteed non-destructive cleanup.
func ExecuteCanaryLifecycle(ctx context.Context, op CanaryOperation) error {
	if op == nil {
		return errors.New("nil canary operation")
	}

	// Step 1: Pre-check to guarantee no existing data is overwritten
	if err := op.PreCheck(ctx); err != nil {
		return fmt.Errorf("canary pre-check failed (aborting to prevent data overwrite): %w", err)
	}

	// Step 2: Execute write
	if err := op.Execute(ctx); err != nil {
		return fmt.Errorf("canary write failed: %w", err)
	}

	// Ensure cleanup is always attempted after execute succeeds
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = op.Cleanup(cleanupCtx)
	}()

	// Step 3: Verify read-back of written canary
	if err := op.Verify(ctx); err != nil {
		return fmt.Errorf("canary verification read-back failed: %w", err)
	}

	return nil
}
