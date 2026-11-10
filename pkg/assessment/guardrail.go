package assessment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// Common guardrail errors.
var (
	ErrManifestInvalid          = errors.New("guardrail refusal: scope manifest is missing, malformed, or invalid")
	ErrEmptyScope                = errors.New("guardrail refusal: scope manifest contains no allowed hosts (fail-closed)")
	ErrOutOfScopeHost            = errors.New("guardrail refusal: destination host is not authorized by scope manifest")
	ErrOutOfScopePath            = errors.New("guardrail refusal: destination path is not authorized by scope manifest")
	ErrUnauthorizedMethod        = errors.New("guardrail refusal: HTTP method is not permitted by scope manifest")
	ErrBlacklistedPaymentRoute   = errors.New("guardrail refusal: destructive payment route unconditionally prohibited")
	ErrUnauthorizedAdminDelete   = errors.New("guardrail refusal: HTTP DELETE against administrative endpoint unauthorized")
	ErrOriginStrainBackoff       = errors.New("guardrail refusal: origin undergoing dynamic WAF backoff throttle")
	ErrDisallowedResolvedAddress = errors.New("guardrail refusal: destination resolved to prohibited IP address")
)

// -----------------------------------------------------------------------------
// 1. Declarative Scope Manifest Models (`felix.pentest.yml`)
// -----------------------------------------------------------------------------

// PentestManifest defines the declarative pre-flight scope defense policy.
type PentestManifest struct {
	Version      string              `yaml:"version" json:"version"`
	Metadata     ManifestMetadata    `yaml:"metadata" json:"metadata"`
	Scope        ScopeConfig         `yaml:"scope" json:"scope"`
	OriginHealth *OriginHealthConfig `yaml:"origin_health,omitempty" json:"origin_health,omitempty"`
}

// ManifestMetadata provides provenance and audit trail for the pentest policy.
type ManifestMetadata struct {
	AssessmentID string    `yaml:"assessment_id" json:"assessment_id"`
	ClientName   string    `yaml:"client_name" json:"client_name"`
	CreatedAt    time.Time `yaml:"created_at" json:"created_at"`
	Description  string    `yaml:"description" json:"description"`
}

// ScopeConfig specifies explicitly allowed hosts, paths, methods, and admin permissions.
type ScopeConfig struct {
	AllowedHosts     []string           `yaml:"allowed_hosts" json:"allowed_hosts"`
	AllowedPaths     []string           `yaml:"allowed_paths" json:"allowed_paths"`
	AllowedMethods   []string           `yaml:"allowed_methods" json:"allowed_methods"`
	AllowAdminDelete *AdminDeleteConfig `yaml:"allow_admin_delete,omitempty" json:"allow_admin_delete,omitempty"`
}

// AdminDeleteConfig provides narrow, auditable permission for administrative DELETE actions.
type AdminDeleteConfig struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	AuthorizedEndpoints []string `yaml:"authorized_endpoints" json:"authorized_endpoints"`
	AuthorizedBy        string   `yaml:"authorized_by" json:"authorized_by"`
	Justification       string   `yaml:"justification" json:"justification"`
}

// OriginHealthConfig configures dynamic WAF and strain-based backoff thresholds.
type OriginHealthConfig struct {
	StrainThreshold      int           `yaml:"strain_threshold" json:"strain_threshold"`           // Consecutive/rolling strain errors before backoff
	RollingWindow        time.Duration `yaml:"rolling_window" json:"rolling_window"`               // Time window for monitoring error rates
	BackoffDuration      time.Duration `yaml:"backoff_duration" json:"backoff_duration"`           // Base backoff duration (default 30s)
	ThrottledRate        float64       `yaml:"throttled_rate" json:"throttled_rate"`               // Maximum req/sec during throttle/probation
	ThrottledConcurrency int           `yaml:"throttled_concurrency" json:"throttled_concurrency"` // Maximum concurrency during throttle/probation
}

// DefaultOriginHealthConfig returns conservative production origin health defaults.
func DefaultOriginHealthConfig() OriginHealthConfig {
	return OriginHealthConfig{
		StrainThreshold:      3,
		RollingWindow:        10 * time.Second,
		BackoffDuration:      30 * time.Second,
		ThrottledRate:        1.0,
		ThrottledConcurrency: 1,
	}
}

// ParsePentestManifest parses and strictly validates raw YAML scope manifest data.
func ParsePentestManifest(data []byte) (*PentestManifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: manifest data cannot be empty", ErrManifestInvalid)
	}

	var m PentestManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: YAML parsing failed: %v", ErrManifestInvalid, err)
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return &m, nil
}

// ParsePentestManifestFile reads and parses a manifest from disk.
func ParsePentestManifestFile(filePath string) (*PentestManifest, error) {
	cleanPath := filepath.Clean(filePath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed reading manifest file %q: %v", ErrManifestInvalid, filePath, err)
	}
	return ParsePentestManifest(data)
}

// Validate performs strict validation of manifest rules.
func (m *PentestManifest) Validate() error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrManifestInvalid)
	}

	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: version field is required", ErrManifestInvalid)
	}

	// Scope validation (fail-closed)
	if len(m.Scope.AllowedHosts) == 0 {
		return fmt.Errorf("%w: allowed_hosts cannot be empty", ErrEmptyScope)
	}

	for _, h := range m.Scope.AllowedHosts {
		hClean := strings.TrimSpace(strings.ToLower(h))
		if hClean == "" || hClean == "*" || hClean == "*.*" {
			return fmt.Errorf("%w: wildcard or blank host %q prohibited (fail-closed)", ErrManifestInvalid, h)
		}
	}

	if len(m.Scope.AllowedPaths) == 0 {
		return fmt.Errorf("%w: allowed_paths cannot be empty (specify explicit paths like [\"/\"])", ErrEmptyScope)
	}

	if len(m.Scope.AllowedMethods) == 0 {
		return fmt.Errorf("%w: allowed_methods cannot be empty (specify explicit methods like [\"GET\", \"POST\"])", ErrEmptyScope)
	}

	// Validate AdminDelete configuration if enabled
	if m.Scope.AllowAdminDelete != nil && m.Scope.AllowAdminDelete.Enabled {
		if strings.TrimSpace(m.Scope.AllowAdminDelete.AuthorizedBy) == "" {
			return fmt.Errorf("%w: allow_admin_delete requires non-empty authorized_by", ErrManifestInvalid)
		}
		if strings.TrimSpace(m.Scope.AllowAdminDelete.Justification) == "" {
			return fmt.Errorf("%w: allow_admin_delete requires non-empty justification", ErrManifestInvalid)
		}
		if len(m.Scope.AllowAdminDelete.AuthorizedEndpoints) == 0 {
			return fmt.Errorf("%w: allow_admin_delete requires explicit authorized_endpoints", ErrManifestInvalid)
		}
	}

	// Validate OriginHealth defaults if nil
	if m.OriginHealth == nil {
		def := DefaultOriginHealthConfig()
		m.OriginHealth = &def
	} else {
		if m.OriginHealth.StrainThreshold <= 0 {
			m.OriginHealth.StrainThreshold = 3
		}
		if m.OriginHealth.RollingWindow <= 0 {
			m.OriginHealth.RollingWindow = 10 * time.Second
		}
		if m.OriginHealth.BackoffDuration <= 0 {
			m.OriginHealth.BackoffDuration = 30 * time.Second
		}
		if m.OriginHealth.ThrottledRate <= 0 {
			m.OriginHealth.ThrottledRate = 1.0
		}
		if m.OriginHealth.ThrottledConcurrency <= 0 {
			m.OriginHealth.ThrottledConcurrency = 1
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// 2. Destructive Action Blacklist & Normalization Engine
// -----------------------------------------------------------------------------

// Hardcoded, unconditionally prohibited payment routes.
var blacklistedPaymentRoutes = []string{
	"/checkout/pay",
	"/billing/charge",
	"/payment/execute",
}

// Sensitive administrative path segments subject to DELETE protection.
var adminDeletePathKeywords = []string{
	"/admin",
	"/administrator",
	"/user",
	"/users",
	"/account",
	"/accounts",
	"/member",
	"/members",
	"/role",
	"/roles",
}

// BlockedOperationResult captures structured diagnostic information when a request is blocked.
type BlockedOperationResult struct {
	Blocked           bool      `json:"blocked"`
	Reason            string    `json:"reason"`
	TargetURL         string    `json:"target_url"`
	Method            string    `json:"method"`
	MatchedRule       string    `json:"matched_rule"`
	BlacklistCategory string    `json:"blacklist_category"`
	Timestamp         time.Time `json:"timestamp"`
}

// BlockedOperationError wraps a BlockedOperationResult as a Go error.
type BlockedOperationError struct {
	Result BlockedOperationResult
}

func (e *BlockedOperationError) Error() string {
	return fmt.Sprintf("guardrail blocked %s %s [%s]: %s",
		e.Result.Method, e.Result.TargetURL, e.Result.BlacklistCategory, e.Result.Reason)
}

func (e *BlockedOperationError) Unwrap() error {
	switch e.Result.BlacklistCategory {
	case "PAYMENT_ROUTE":
		return ErrBlacklistedPaymentRoute
	case "UNAUTHORIZED_ADMIN_DELETE":
		return ErrUnauthorizedAdminDelete
	case "OUT_OF_SCOPE_HOST":
		return ErrOutOfScopeHost
	case "OUT_OF_SCOPE_PATH":
		return ErrOutOfScopePath
	case "UNAUTHORIZED_METHOD":
		return ErrUnauthorizedMethod
	case "AMBIGUOUS_ENCODING":
		return ErrManifestInvalid
	default:
		return ErrManifestInvalid
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// CanonicalPath performs rigorous canonical path resolution:
// - strips query strings and fragments
// - detects and rejects ambiguous input (null bytes, malformed percent escapes, excessive nesting)
// - strips semicolon matrix/path parameters per segment
// - decodes percent-encoding safely (up to 3 rounds)
// - collapses multiple slashes and resolves dot-segment traversals
// Returns:
//   canonical: clean path preserving original case (for case-sensitive allowlist matching)
//   lowercased: lowercased clean path (for case-insensitive blacklist matching)
//   isAmbiguous: true if input contains malformed or hostile encoding that cannot be canonically resolved
//   reason: description of ambiguous encoding
func CanonicalPath(rawPath string) (canonical string, lowercased string, isAmbiguous bool, reason string) {
	if rawPath == "" {
		return "/", "/", false, ""
	}

	// 1. Strip query string and fragment if present
	if idx := strings.IndexAny(rawPath, "?#"); idx != -1 {
		rawPath = rawPath[:idx]
	}

	// 2. Reject null bytes (raw or encoded)
	if strings.Contains(rawPath, "\x00") || strings.Contains(strings.ToLower(rawPath), "%00") {
		return "", "", true, "embedded null byte detected"
	}

	// 3. Reject malformed percent encodings (incomplete % or non-hex)
	for i := 0; i < len(rawPath); i++ {
		if rawPath[i] == '%' {
			if i+2 >= len(rawPath) || !isHex(rawPath[i+1]) || !isHex(rawPath[i+2]) {
				return "", "", true, fmt.Sprintf("malformed percent-encoding near index %d", i)
			}
		}
	}

	// 4. Safely decode percent-encoding iteratively (up to 3 rounds)
	decoded := rawPath
	for round := 0; round < 3; round++ {
		unescaped, err := url.PathUnescape(decoded)
		if err != nil {
			return "", "", true, fmt.Sprintf("percent-decoding error: %v", err)
		}
		if unescaped == decoded {
			break
		}
		decoded = unescaped
	}

	// 5. Check for remaining unescaped percent sequences (nested recursive encoding attempt)
	for i := 0; i < len(decoded); i++ {
		if decoded[i] == '%' && i+2 < len(decoded) && isHex(decoded[i+1]) && isHex(decoded[i+2]) {
			return "", "", true, "excessive recursive percent-encoding beyond 3 rounds detected"
		}
	}

	// 6. Strip semicolon matrix parameters per segment (e.g. /checkout/pay;jsessionid=123 -> /checkout/pay)
	segments := strings.Split(decoded, "/")
	for i, seg := range segments {
		if idx := strings.Index(seg, ";"); idx != -1 {
			segments[i] = seg[:idx]
		}
	}
	stripped := strings.Join(segments, "/")

	// 7. Ensure leading slash and clean dot segments and duplicate slashes
	if !strings.HasPrefix(stripped, "/") {
		stripped = "/" + stripped
	}
	clean := path.Clean(stripped)
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}

	return clean, strings.ToLower(clean), false, ""
}

// NormalizePath performs canonical path resolution, preserving compatibility.
func NormalizePath(rawPath string) string {
	canonical, _, _, _ := CanonicalPath(rawPath)
	if canonical == "" {
		return "/"
	}
	return canonical
}

// NormalizePathLower returns the lowercased canonical path for blacklist evaluation.
func NormalizePathLower(rawPath string) string {
	_, lowercased, _, _ := CanonicalPath(rawPath)
	if lowercased == "" {
		return "/"
	}
	return lowercased
}

// CheckDestructiveAction evaluates whether an HTTP method and URL attempt a prohibited destructive action.
func CheckDestructiveAction(method string, targetURL *url.URL, manifest *PentestManifest) *BlockedOperationResult {
	if targetURL == nil {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            "target URL is nil",
			BlacklistCategory: "MALFORMED_URL",
			Timestamp:         time.Now().UTC(),
		}
	}

	canonical, lowerPath, isAmbiguous, reason := CanonicalPath(targetURL.Path)
	methodUpper := strings.ToUpper(strings.TrimSpace(method))
	redactedURL := secrets.RedactText(targetURL.String())

	if isAmbiguous {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            fmt.Sprintf("ambiguous or hostile path encoding rejected: %s", reason),
			TargetURL:         redactedURL,
			Method:            methodUpper,
			MatchedRule:       targetURL.Path,
			BlacklistCategory: "AMBIGUOUS_ENCODING",
			Timestamp:         time.Now().UTC(),
		}
	}

	// 1. Always evaluate the three hardcoded payment routes (unconditional refusal)
	// Checked against lowerPath to catch ALL case variations (/CHECKOUT/PAY, /checkout/pay, etc.)
	for _, blRoute := range blacklistedPaymentRoutes {
		normBL := strings.ToLower(blRoute)
		if lowerPath == normBL || strings.HasPrefix(lowerPath, normBL+"/") {
			return &BlockedOperationResult{
				Blocked:           true,
				Reason:            fmt.Sprintf("target path %q matches hardcoded destructive payment route %q", canonical, blRoute),
				TargetURL:         redactedURL,
				Method:            methodUpper,
				MatchedRule:       blRoute,
				BlacklistCategory: "PAYMENT_ROUTE",
				Timestamp:         time.Now().UTC(),
			}
		}
	}

	// 2. Evaluate administrative DELETE actions
	if methodUpper == "DELETE" {
		isAdminEndpoint := false
		matchedKeyword := ""
		for _, kw := range adminDeletePathKeywords {
			if strings.Contains(lowerPath, kw) {
				isAdminEndpoint = true
				matchedKeyword = kw
				break
			}
		}

		if isAdminEndpoint {
			// Check if explicit narrow authorization exists in manifest
			authorized := false
			if manifest != nil && manifest.Scope.AllowAdminDelete != nil && manifest.Scope.AllowAdminDelete.Enabled {
				for _, authEp := range manifest.Scope.AllowAdminDelete.AuthorizedEndpoints {
					authCanonical, authLower, _, _ := CanonicalPath(authEp)
					if lowerPath == authLower || canonical == authCanonical ||
						strings.HasPrefix(lowerPath, strings.TrimSuffix(authLower, "*")) ||
						strings.HasPrefix(canonical, strings.TrimSuffix(authCanonical, "*")) {
						authorized = true
						break
					}
				}
			}

			if !authorized {
				return &BlockedOperationResult{
					Blocked:           true,
					Reason:            fmt.Sprintf("HTTP DELETE against administrative endpoint %q blocked without explicit authorization (keyword: %q)", canonical, matchedKeyword),
					TargetURL:         redactedURL,
					Method:            methodUpper,
					MatchedRule:       matchedKeyword,
					BlacklistCategory: "UNAUTHORIZED_ADMIN_DELETE",
					Timestamp:         time.Now().UTC(),
				}
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// 3. Scope Verification Engine
// -----------------------------------------------------------------------------

// CheckScope verifies that an HTTP request adheres to the explicit manifest scope.
func CheckScope(req *http.Request, manifest *PentestManifest) *BlockedOperationResult {
	if manifest == nil {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            "scope manifest is nil (fail-closed)",
			BlacklistCategory: "MANIFEST_NIL",
			Timestamp:         time.Now().UTC(),
		}
	}

	if req == nil || req.URL == nil {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            "request or URL is nil (fail-closed)",
			BlacklistCategory: "MALFORMED_REQUEST",
			Timestamp:         time.Now().UTC(),
		}
	}

	redactedURL := secrets.RedactText(req.URL.String())
	methodUpper := strings.ToUpper(strings.TrimSpace(req.Method))
	if methodUpper == "" {
		methodUpper = "GET"
	}

	// 1. Method Authorization Check
	methodAllowed := false
	for _, m := range manifest.Scope.AllowedMethods {
		if strings.EqualFold(m, methodUpper) {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            fmt.Sprintf("HTTP method %q is not authorized by scope manifest", methodUpper),
			TargetURL:         redactedURL,
			Method:            methodUpper,
			MatchedRule:       strings.Join(manifest.Scope.AllowedMethods, ","),
			BlacklistCategory: "UNAUTHORIZED_METHOD",
			Timestamp:         time.Now().UTC(),
		}
	}

	// 2. Host Authorization Check (prevent suffix/prefix confusion)
	reqHost := strings.ToLower(req.URL.Hostname())
	if reqHost == "" {
		reqHost = strings.ToLower(req.Host)
		if idx := strings.Index(reqHost, ":"); idx != -1 {
			reqHost = reqHost[:idx]
		}
	}

	reqPort := req.URL.Port()
	if reqPort == "" {
		if strings.EqualFold(req.URL.Scheme, "https") {
			reqPort = "443"
		} else {
			reqPort = "80"
		}
	}

	hostAllowed := false

	for _, allowed := range manifest.Scope.AllowedHosts {
		cleanAllowed := strings.TrimSpace(strings.ToLower(allowed))
		allowedHostOnly := cleanAllowed
		allowedPortOnly := ""

		if strings.Contains(cleanAllowed, ":") {
			if h, p, err := net.SplitHostPort(cleanAllowed); err == nil {
				allowedHostOnly = h
				allowedPortOnly = p
			}
		}

		// Exact host match required (prevents attacker.com.example.com or notexample.com)
		if reqHost == allowedHostOnly {
			if allowedPortOnly == "" || allowedPortOnly == reqPort {
				hostAllowed = true
				break
			}
		}
	}

	if !hostAllowed {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            fmt.Sprintf("destination host %q (port %s) is not in manifest allowed_hosts", reqHost, reqPort),
			TargetURL:         redactedURL,
			Method:            methodUpper,
			MatchedRule:       strings.Join(manifest.Scope.AllowedHosts, ","),
			BlacklistCategory: "OUT_OF_SCOPE_HOST",
			Timestamp:         time.Now().UTC(),
		}
	}

	// 3. Destructive Blacklist Check (evaluated before path allowlist so payment routes are unconditionally blocked)
	if bl := CheckDestructiveAction(methodUpper, req.URL, manifest); bl != nil {
		return bl
	}

	// 4. Path Authorization Check
	canonical, _, isAmbiguous, reason := CanonicalPath(req.URL.Path)
	if isAmbiguous {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            fmt.Sprintf("ambiguous or hostile path encoding rejected: %s", reason),
			TargetURL:         redactedURL,
			Method:            methodUpper,
			MatchedRule:       req.URL.Path,
			BlacklistCategory: "AMBIGUOUS_ENCODING",
			Timestamp:         time.Now().UTC(),
		}
	}

	pathAllowed := false

	for _, allowedP := range manifest.Scope.AllowedPaths {
		cleanAllowed, _, _, _ := CanonicalPath(allowedP)
		if cleanAllowed == "/" {
			pathAllowed = true
			break
		}
		// Match exact or child prefix boundary with case sensitivity to prevent lowercasing bypass
		if canonical == cleanAllowed || strings.HasPrefix(canonical, strings.TrimSuffix(cleanAllowed, "/")+"/") {
			pathAllowed = true
			break
		}
	}

	if !pathAllowed {
		return &BlockedOperationResult{
			Blocked:           true,
			Reason:            fmt.Sprintf("destination path %q is not authorized by manifest allowed_paths", canonical),
			TargetURL:         redactedURL,
			Method:            methodUpper,
			MatchedRule:       strings.Join(manifest.Scope.AllowedPaths, ","),
			BlacklistCategory: "OUT_OF_SCOPE_PATH",
			Timestamp:         time.Now().UTC(),
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// 4. Dynamic WAF & Origin-Health Monitoring Engine
// -----------------------------------------------------------------------------

// OriginHealthState indicates the operational health status of a target origin.
type OriginHealthState string

const (
	HealthStateNormal    OriginHealthState = "NORMAL"
	HealthStateBackoff   OriginHealthState = "BACKOFF"
	HealthStateProbation OriginHealthState = "PROBATION"
)

// OriginState tracks rolling response errors and active throttle state for a specific origin.
type OriginState struct {
	Origin               string
	State                OriginHealthState
	ErrorTimestamps      []time.Time
	BackoffUntil         time.Time
	EffectiveRate        float64
	EffectiveConcurrency int
	ActiveRequests       int
	LastDispatch         time.Time
	mu                   sync.Mutex
}

// OriginHealthTracker coordinates rolling window error monitoring and adaptive throttling.
type OriginHealthTracker struct {
	cfg       OriginHealthConfig
	origins   map[string]*OriginState
	mu        sync.RWMutex
	clock     func() time.Time
	sleepFunc func(ctx context.Context, d time.Duration) error

	// Telemetry metrics
	totalWAFEvents    atomic.Int64
	totalBackoffCount atomic.Int64
	totalThrottledReq atomic.Int64
}

// NewOriginHealthTracker constructs a thread-safe origin health monitor.
func NewOriginHealthTracker(cfg OriginHealthConfig) *OriginHealthTracker {
	return &OriginHealthTracker{
		cfg:     cfg,
		origins: make(map[string]*OriginState),
		clock:   time.Now,
		sleepFunc: func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return nil
			}
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}
}

// SetClock allows injecting a custom time provider for deterministic testing.
func (t *OriginHealthTracker) SetClock(clock func() time.Time, sleeper func(ctx context.Context, d time.Duration) error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clock = clock
	t.sleepFunc = sleeper
}

func (t *OriginHealthTracker) getOrCreateOriginState(origin string) *OriginState {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.origins[origin]
	if !ok {
		s = &OriginState{
			Origin:               origin,
			State:                HealthStateNormal,
			EffectiveRate:        0, // unlimited by default unless throttled
			EffectiveConcurrency: 0, // unlimited by default unless throttled
		}
		t.origins[origin] = s
	}
	return s
}

// ObserveResponse monitors outbound HTTP response codes (429, 503, 504) for origin strain.
func (t *OriginHealthTracker) ObserveResponse(origin string, statusCode int, header http.Header) {
	// Only 429, 503, and 504 trigger origin strain tracking
	if statusCode != http.StatusTooManyRequests &&
		statusCode != http.StatusServiceUnavailable &&
		statusCode != http.StatusGatewayTimeout {
		// Non-strain response: check if probation can be cleared
		t.recordSuccess(origin)
		return
	}

	t.totalWAFEvents.Add(1)
	st := t.getOrCreateOriginState(origin)
	st.mu.Lock()
	defer st.mu.Unlock()

	now := t.clock()

	// 1. Add timestamp and prune rolling window
	st.ErrorTimestamps = append(st.ErrorTimestamps, now)
	cutoff := now.Add(-t.cfg.RollingWindow)
	validIdx := 0
	for i, ts := range st.ErrorTimestamps {
		if ts.After(cutoff) {
			validIdx = i
			break
		}
	}
	st.ErrorTimestamps = st.ErrorTimestamps[validIdx:]

	// 2. Check if rolling strain threshold is met
	if len(st.ErrorTimestamps) >= t.cfg.StrainThreshold {
		st.State = HealthStateBackoff
		t.totalBackoffCount.Add(1)

		backoffDur := t.cfg.BackoffDuration
		// Parse Retry-After if provided (delta-seconds or HTTP-date RFC 7231)
		if header != nil {
			if ra := header.Get("Retry-After"); ra != "" {
				if sec, err := strconv.Atoi(ra); err == nil && sec > 0 {
					raDur := time.Duration(sec) * time.Second
					if raDur > backoffDur {
						backoffDur = raDur
					}
				} else if targetTime, err := http.ParseTime(ra); err == nil {
					raDur := targetTime.Sub(now)
					if raDur > backoffDur {
						backoffDur = raDur
					}
				}
			}
		}

		st.BackoffUntil = now.Add(backoffDur)
		st.EffectiveRate = t.cfg.ThrottledRate
		st.EffectiveConcurrency = t.cfg.ThrottledConcurrency
	}
}

func (t *OriginHealthTracker) recordSuccess(origin string) {
	st := t.getOrCreateOriginState(origin)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.State == HealthStateProbation {
		// Recovery successful: restore normal health state
		st.State = HealthStateNormal
		st.EffectiveRate = 0
		st.EffectiveConcurrency = 0
		st.ErrorTimestamps = nil
	}
}

// Acquire waits for any active backoff period to expire and enforces throttled pacing.
func (t *OriginHealthTracker) Acquire(ctx context.Context, origin string) error {
	st := t.getOrCreateOriginState(origin)

	for {
		st.mu.Lock()
		now := t.clock()

		// 1. Check if in active backoff
		if st.State == HealthStateBackoff {
			if now.Before(st.BackoffUntil) {
				waitDur := st.BackoffUntil.Sub(now)
				st.mu.Unlock()
				t.totalThrottledReq.Add(1)
				if err := t.sleepFunc(ctx, waitDur); err != nil {
					return err
				}
				continue
			}
			// Backoff expired: transition to PROBATION
			st.State = HealthStateProbation
		}

		// 2. Enforce concurrency restriction if throttled/probation
		if st.EffectiveConcurrency > 0 && st.ActiveRequests >= st.EffectiveConcurrency {
			st.mu.Unlock()
			t.totalThrottledReq.Add(1)
			if err := t.sleepFunc(ctx, 50*time.Millisecond); err != nil {
				return err
			}
			continue
		}

		// 3. Enforce rate limit interval if throttled
		if st.EffectiveRate > 0 {
			minInterval := time.Duration(float64(time.Second) / st.EffectiveRate)
			if !st.LastDispatch.IsZero() {
				elapsed := now.Sub(st.LastDispatch)
				if elapsed < minInterval {
					waitDur := minInterval - elapsed
					st.mu.Unlock()
					t.totalThrottledReq.Add(1)
					if err := t.sleepFunc(ctx, waitDur); err != nil {
						return err
					}
					continue
				}
			}
			st.LastDispatch = now
		}

		st.ActiveRequests++
		st.mu.Unlock()
		return nil
	}
}

// Release decrements active request count upon completion.
func (t *OriginHealthTracker) Release(origin string) {
	st := t.getOrCreateOriginState(origin)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.ActiveRequests > 0 {
		st.ActiveRequests--
	}
}

// GetOriginHealthStatus returns a snapshot of an origin's throttle and health metrics.
func (t *OriginHealthTracker) GetOriginHealthStatus(origin string) (OriginHealthState, time.Time, int) {
	st := t.getOrCreateOriginState(origin)
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.State, st.BackoffUntil, len(st.ErrorTimestamps)
}

// -----------------------------------------------------------------------------
// 5. Central Outbound Guardrail Transport & HTTP Client
// -----------------------------------------------------------------------------

// GuardrailOptions configures the central guardrail round-tripper.
type GuardrailOptions struct {
	BaseTransport http.RoundTripper
	SSRF          crawler.SafeTransportOptions
	OriginHealth  OriginHealthConfig
}

// GuardrailTransport implements http.RoundTripper enforcing all Phase 9.4 guardrails.
type GuardrailTransport struct {
	manifest     *PentestManifest
	health       *OriginHealthTracker
	base         http.RoundTripper
	ssrfOptions  crawler.SafeTransportOptions
	blockedCalls atomic.Int64
}

// NewGuardrailTransport constructs the centralized guardrail transport.
func NewGuardrailTransport(manifest *PentestManifest, opts GuardrailOptions) (*GuardrailTransport, error) {
	if manifest == nil {
		return nil, fmt.Errorf("%w: cannot construct GuardrailTransport without PentestManifest", ErrManifestInvalid)
	}

	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	base := opts.BaseTransport
	if base == nil {
		base = crawler.NewSafeTransport(opts.SSRF)
	}

	healthCfg := opts.OriginHealth
	if manifest.OriginHealth != nil {
		healthCfg = *manifest.OriginHealth
	}

	return &GuardrailTransport{
		manifest:    manifest,
		health:      NewOriginHealthTracker(healthCfg),
		base:        base,
		ssrfOptions: opts.SSRF,
	}, nil
}

// OriginOf returns the canonical origin string (scheme://host:port) for rate limiting.
func OriginOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return fmt.Sprintf("%s://%s:%s", strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), port)
}

// RoundTrip executes outbound request policy validation, origin rate-limiting, and response monitoring.
func (g *GuardrailTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("cannot dispatch nil request")
	}

	// 1. Centralized Scope & Destructive Blacklist Check
	if bl := CheckScope(req, g.manifest); bl != nil && bl.Blocked {
		g.blockedCalls.Add(1)
		return nil, &BlockedOperationError{Result: *bl}
	}

	origin := OriginOf(req.URL)

	// 2. Dynamic WAF & Rate-Limit Backoff Pacing
	if err := g.health.Acquire(req.Context(), origin); err != nil {
		return nil, err
	}
	defer g.health.Release(origin)

	// 3. Dispatch to underlying secure transport
	resp, err := g.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// 4. Observe response status for WAF strain indicators
	g.health.ObserveResponse(origin, resp.StatusCode, resp.Header)

	return resp, nil
}

// HealthTracker returns the internal OriginHealthTracker.
func (g *GuardrailTransport) HealthTracker() *OriginHealthTracker {
	return g.health
}

// BlockedCalls returns cumulative count of blocked requests intercepted by guardrail.
func (g *GuardrailTransport) BlockedCalls() int64 {
	return g.blockedCalls.Load()
}

// NewGuardrailHTTPClient constructs an http.Client pre-configured with the centralized guardrail transport
// and safe redirect verification.
func NewGuardrailHTTPClient(manifest *PentestManifest, opts GuardrailOptions) (*http.Client, error) {
	gt, err := NewGuardrailTransport(manifest, opts)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: gt,
		Timeout:   opts.SSRF.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects (potential redirect loop)")
			}

			// Validate next redirect destination against manifest scope & blacklist
			if bl := CheckScope(req, manifest); bl != nil && bl.Blocked {
				return fmt.Errorf("redirect to %s blocked: %s", req.URL.String(), bl.Reason)
			}

			return nil
		},
	}

	return client, nil
}
