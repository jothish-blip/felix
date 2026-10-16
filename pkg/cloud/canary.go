package cloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
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

	// Condition 8: Least-privilege identity confirmed (cannot infer from role name alone)
	if !canary.IdentityLeastPrivilegeVerified || !identityMinPrivilege {
		return CanaryEvaluationResult{
			Allowed: false,
			Reason:  "identity is not explicitly verified as least-privilege for canary operation; authorization cannot be inferred from a configuration default or role name alone",
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
	PreCheck(ctx context.Context) error // Check if resource already exists to prevent overwrite
	Execute(ctx context.Context) error  // Execute isolated write
	Verify(ctx context.Context) error   // Confirm write succeeded
	Cleanup(ctx context.Context) error  // Non-destructive cleanup of written canary
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

// RedisCanaryOperation executes isolated, non-destructive canary writes on Redis using NX and compare-and-delete cleanup.
type RedisCanaryOperation struct {
	Client    *Client
	Addr      string
	CanaryKey string
	CanaryVal string
	Cred      *CredentialProfile
	written   bool
	cleaned   bool
}

func (r *RedisCanaryOperation) PreCheck(ctx context.Context) error {
	conn, err := r.Client.SafeDialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if r.Cred != nil && r.Cred.Secret != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", r.Cred.Secret)
		if r.Cred.Username != "" {
			authCmd = fmt.Sprintf("AUTH %s %s\r\n", r.Cred.Username, r.Cred.Secret)
		}
		_, _ = conn.Write([]byte(authCmd))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
	}

	// Check EXISTS
	cmd := fmt.Sprintf("EXISTS %s\r\n", r.CanaryKey)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	resp := string(buf[:n])
	if strings.HasPrefix(resp, ":1") {
		return fmt.Errorf("canary key %q already exists in Redis; write aborted to prevent overwrite", r.CanaryKey)
	}
	return nil
}

func (r *RedisCanaryOperation) Execute(ctx context.Context) error {
	conn, err := r.Client.SafeDialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if r.Cred != nil && r.Cred.Secret != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", r.Cred.Secret)
		if r.Cred.Username != "" {
			authCmd = fmt.Sprintf("AUTH %s %s\r\n", r.Cred.Username, r.Cred.Secret)
		}
		_, _ = conn.Write([]byte(authCmd))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
	}

	// SET key val NX EX 60 (expires in 60s as backup safeguard)
	setCmd := fmt.Sprintf("SET %s %s NX EX 60\r\n", r.CanaryKey, r.CanaryVal)
	if _, err := conn.Write([]byte(setCmd)); err != nil {
		return err
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "+OK") {
		r.written = false
		return fmt.Errorf("Redis SETNX rejected: %s", strings.TrimSpace(resp))
	}
	r.written = true
	return nil
}

func (r *RedisCanaryOperation) Verify(ctx context.Context) error {
	if !r.written {
		return errors.New("canary write was not executed")
	}

	conn, err := r.Client.SafeDialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if r.Cred != nil && r.Cred.Secret != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", r.Cred.Secret)
		if r.Cred.Username != "" {
			authCmd = fmt.Sprintf("AUTH %s %s\r\n", r.Cred.Username, r.Cred.Secret)
		}
		_, _ = conn.Write([]byte(authCmd))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
	}

	getCmd := fmt.Sprintf("GET %s\r\n", r.CanaryKey)
	if _, err := conn.Write([]byte(getCmd)); err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, r.CanaryVal) {
		return fmt.Errorf("Redis GET verify returned unexpected value: %s", strings.TrimSpace(resp))
	}
	return nil
}

func (r *RedisCanaryOperation) Cleanup(ctx context.Context) error {
	if !r.written {
		// Key was never written by this operation; cleanup must not touch the server
		return nil
	}
	if r.cleaned {
		// Repeated cleanup is a safe no-op
		return nil
	}

	conn, err := r.Client.SafeDialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if r.Cred != nil && r.Cred.Secret != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", r.Cred.Secret)
		if r.Cred.Username != "" {
			authCmd = fmt.Sprintf("AUTH %s %s\r\n", r.Cred.Username, r.Cred.Secret)
		}
		_, _ = conn.Write([]byte(authCmd))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
	}

	// Atomic compare-and-delete using Lua script:
	// Only delete the key if it still contains our exact CanaryVal.
	luaScript := "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
	evalCmd := fmt.Sprintf("EVAL %q 1 %s %s\r\n", luaScript, r.CanaryKey, r.CanaryVal)
	if _, err := conn.Write([]byte(evalCmd)); err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	resp := string(buf[:n])

	if strings.HasPrefix(resp, ":1") {
		// Key matched CanaryVal and was atomically deleted
		r.cleaned = true
		r.written = false
		return nil
	} else if strings.HasPrefix(resp, ":0") {
		// Value did not match (ownership changed) or key was already deleted
		return fmt.Errorf("canary key ownership mismatch for %q: key value has changed or key was replaced by another process; cleanup refused to delete foreign key", r.CanaryKey)
	} else if strings.HasPrefix(resp, "-ERR") {
		// Fallback for Redis instances where EVAL is disabled: use WATCH / GET / MULTI / DEL / EXEC
		watchCmd := fmt.Sprintf("WATCH %s\r\nGET %s\r\n", r.CanaryKey, r.CanaryKey)
		if _, err := conn.Write([]byte(watchCmd)); err != nil {
			return err
		}
		wBuf := make([]byte, 256)
		wn, _ := conn.Read(wBuf)
		wResp := string(wBuf[:wn])
		if !strings.Contains(wResp, r.CanaryVal) {
			_, _ = conn.Write([]byte("UNWATCH\r\n"))
			return fmt.Errorf("canary key ownership mismatch for %q: key has changed or was replaced; cleanup aborted", r.CanaryKey)
		}
		txCmd := fmt.Sprintf("MULTI\r\nDEL %s\r\nEXEC\r\n", r.CanaryKey)
		if _, err := conn.Write([]byte(txCmd)); err != nil {
			return err
		}
		txBuf := make([]byte, 256)
		txn, _ := conn.Read(txBuf)
		txResp := string(txBuf[:txn])
		if strings.Contains(txResp, "*-1") || strings.Contains(txResp, "$0") {
			return fmt.Errorf("concurrent modification detected during cleanup of %q", r.CanaryKey)
		}
		r.cleaned = true
		r.written = false
		return nil
	}

	return fmt.Errorf("unexpected response from Redis compare-and-delete: %s", strings.TrimSpace(resp))
}

// S3CanaryOperation executes isolated, non-destructive canary writes on S3-compatible storage.
type S3CanaryOperation struct {
	Client      *Client
	TargetURL   string
	Resource    string
	Payload     string
	Cred        *CredentialProfile
	canaryToken string
	createdETag string
	written     bool
	cleaned     bool
}

func (s *S3CanaryOperation) PreCheck(ctx context.Context) error {
	cleanURL := strings.TrimRight(s.TargetURL, "/") + "/" + strings.TrimLeft(s.Resource, "/")
	req, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
	if err != nil {
		return err
	}
	if s.Cred != nil && s.Cred.Headers != nil {
		for k, v := range s.Cred.Headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.Client.Do(ctx, req)
	if err == nil && resp.StatusCode == http.StatusOK {
		return fmt.Errorf("canary object %q already exists; write aborted to prevent overwrite", s.Resource)
	}
	return nil
}

func (s *S3CanaryOperation) Execute(ctx context.Context) error {
	if s.canaryToken == "" {
		s.canaryToken = fmt.Sprintf("felix-canary-token-%d", time.Now().UnixNano())
	}

	cleanURL := strings.TrimRight(s.TargetURL, "/") + "/" + strings.TrimLeft(s.Resource, "/")
	req, err := http.NewRequestWithContext(ctx, "PUT", cleanURL, bytes.NewReader([]byte(s.Payload)))
	if err != nil {
		return err
	}
	req.Header.Set("If-None-Match", "*") // Prevent overwrite
	req.Header.Set("x-amz-meta-felix-canary", s.canaryToken)
	if s.Cred != nil && s.Cred.Headers != nil {
		for k, v := range s.Cred.Headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.Client.Do(ctx, req)
	if err != nil {
		s.written = false
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		s.written = false
		return fmt.Errorf("S3 PUT canary rejected (HTTP %d)", resp.StatusCode)
	}

	s.written = true
	s.createdETag = resp.Header.Get("ETag")
	return nil
}

func (s *S3CanaryOperation) Verify(ctx context.Context) error {
	if !s.written {
		return errors.New("canary write was not executed")
	}

	cleanURL := strings.TrimRight(s.TargetURL, "/") + "/" + strings.TrimLeft(s.Resource, "/")
	req, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
	if err != nil {
		return err
	}
	if s.Cred != nil && s.Cred.Headers != nil {
		for k, v := range s.Cred.Headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.Client.Do(ctx, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("S3 HEAD verify returned HTTP %d", resp.StatusCode)
	}

	// Verify ETag matches the created object if ETag was captured
	if s.createdETag != "" {
		currETag := resp.Header.Get("ETag")
		if currETag != "" && currETag != s.createdETag {
			return fmt.Errorf("canary verification ETag mismatch: expected %s, got %s", s.createdETag, currETag)
		}
	}

	return nil
}

func (s *S3CanaryOperation) Cleanup(ctx context.Context) error {
	if !s.written {
		// Object was never written by this operation; cleanup must not touch the server
		return nil
	}
	if s.cleaned {
		// Repeated cleanup is a safe no-op
		return nil
	}

	cleanURL := strings.TrimRight(s.TargetURL, "/") + "/" + strings.TrimLeft(s.Resource, "/")

	// Concurrency & Ownership Guardrail: Verify object identity before deletion
	checkReq, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
	if err == nil {
		if s.Cred != nil && s.Cred.Headers != nil {
			for k, v := range s.Cred.Headers {
				checkReq.Header.Set(k, v)
			}
		}
		checkResp, err := s.Client.Do(ctx, checkReq)
		if err == nil {
			if checkResp.StatusCode == http.StatusNotFound {
				// Object already removed
				s.cleaned = true
				s.written = false
				return nil
			}
			if checkResp.StatusCode == http.StatusOK {
				currETag := checkResp.Header.Get("ETag")
				if s.createdETag != "" && currETag != "" && currETag != s.createdETag {
					return fmt.Errorf("canary object ownership mismatch for %q: expected ETag %s, found %s (concurrent replacement detected); cleanup aborted to prevent deleting foreign object", s.Resource, s.createdETag, currETag)
				}
				metaToken := checkResp.Header.Get("x-amz-meta-felix-canary")
				if s.canaryToken != "" && metaToken != "" && metaToken != s.canaryToken {
					return fmt.Errorf("canary object token mismatch for %q: expected %s, found %s (concurrent replacement detected); cleanup aborted to prevent deleting foreign object", s.Resource, s.canaryToken, metaToken)
				}
			}
		}
	}

	// Conditional deletion
	req, err := http.NewRequestWithContext(ctx, "DELETE", cleanURL, nil)
	if err != nil {
		return err
	}
	if s.createdETag != "" {
		req.Header.Set("If-Match", s.createdETag)
	}
	if s.Cred != nil && s.Cred.Headers != nil {
		for k, v := range s.Cred.Headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.Client.Do(ctx, req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		return fmt.Errorf("canary conditional deletion rejected (HTTP 412 Precondition Failed): object was replaced concurrently")
	}
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("canary cleanup rejected (HTTP %d)", resp.StatusCode)
	}

	s.cleaned = true
	s.written = false
	return nil
}

// BuildCanaryOperation constructs an executable CanaryOperation for supported technologies.
func BuildCanaryOperation(
	client *Client,
	target string,
	tech ServiceTechnology,
	canary CanaryConfig,
	cred *CredentialProfile,
) (CanaryOperation, error) {
	switch tech {
	case TechRedis:
		key := canary.CanaryKey
		if key == "" {
			key = canary.TargetResource
		}
		val := canary.CanaryValue
		if val == "" {
			val = fmt.Sprintf("felix-canary-%d", time.Now().UnixNano())
		}
		return &RedisCanaryOperation{
			Client:    client,
			Addr:      target,
			CanaryKey: key,
			CanaryVal: val,
			Cred:      cred,
		}, nil

	case TechAWSS3, TechMinIO:
		val := canary.CanaryValue
		if val == "" {
			val = fmt.Sprintf("felix-canary-%d", time.Now().UnixNano())
		}
		token := fmt.Sprintf("felix-token-%d", time.Now().UnixNano())
		return &S3CanaryOperation{
			Client:      client,
			TargetURL:   target,
			Resource:    canary.TargetResource,
			Payload:     val,
			canaryToken: token,
			Cred:        cred,
		}, nil

	default:
		return nil, fmt.Errorf("canary write verification unsupported for %s", tech)
	}
}
