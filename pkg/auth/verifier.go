package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Predefined error values for verification boundary gates.
var (
	ErrMissingAuthorization = errors.New("security refusal: missing authorization record")
	ErrInvalidAuthorization = errors.New("security refusal: authorization is not currently valid")
	ErrTargetOutOfScope     = errors.New("security refusal: target URL is outside approved scope")
	ErrTargetExcluded       = errors.New("security refusal: target URL matches exclusion rule")
	ErrBudgetExhausted      = errors.New("request budget exhausted")
)

// AuthTestType identifies the specific authentication verification check.
type AuthTestType string

const (
	TestEnforcementBaseline AuthTestType = "ENFORCEMENT_BASELINE"
	TestMissingCredential   AuthTestType = "MISSING_CREDENTIAL"
	TestInvalidCredential   AuthTestType = "INVALID_SYNTHETIC_CREDENTIAL"
	TestEmptyCredential     AuthTestType = "EMPTY_CREDENTIAL"
	TestMalformedHeader     AuthTestType = "MALFORMED_HEADER"
	TestExpiredCredential   AuthTestType = "EXPIRED_CREDENTIAL"
	TestMethodBypass        AuthTestType = "METHOD_BYPASS"
	TestInconsistentRoute   AuthTestType = "INCONSISTENT_ROUTE"
	TestCleartextTransport  AuthTestType = "CLEARTEXT_TRANSPORT"
	TestInformationLeakage  AuthTestType = "INFORMATION_LEAKAGE"
	TestRateLimiting        AuthTestType = "RATE_LIMITING"
	TestUnsupported         AuthTestType = "UNSUPPORTED"
)

// AuthDisposition represents the verdict of an individual verification check.
type AuthDisposition string

const (
	DispositionWeaknessVerified AuthDisposition = "verified_weakness"
	DispositionPassed           AuthDisposition = "passed"
	DispositionCandidate        AuthDisposition = "candidate"
	DispositionSkipped          AuthDisposition = "skipped"
	DispositionFailed           AuthDisposition = "failed"
	DispositionInconclusive     AuthDisposition = "inconclusive"
	DispositionUnsupported      AuthDisposition = "unsupported"
)

// CredentialType identifies the authentication scheme.
type CredentialType string

const (
	CredTypeBearer CredentialType = "bearer"
	CredTypeAPIKey CredentialType = "api_key"
	CredTypeBasic  CredentialType = "basic"
	CredTypeCookie CredentialType = "cookie"
)

// Credential holds test credentials. Credential values are scrubbed in external serializations.
type Credential struct {
	Type       CredentialType `json:"type"`
	Value      string         `json:"-"` // Never serialized in JSON
	HeaderName string         `json:"header_name,omitempty"`
	CookieName string         `json:"cookie_name,omitempty"`
	QueryParam string         `json:"query_param,omitempty"`
	Username   string         `json:"username,omitempty"`
	Password   string         `json:"-"` // Never serialized in JSON
}

// Scrubbed returns a safe redacted representation of the credential.
func (c Credential) Scrubbed() string {
	if c.Value != "" {
		return secrets.RedactSecret(c.Value)
	}
	if c.Password != "" {
		return "[REDACTED_PASSWORD]"
	}
	return "[REDACTED]"
}

// MarshalJSON provides safe JSON serialization without exposing secrets.
func (c Credential) MarshalJSON() ([]byte, error) {
	type Alias Credential
	return json.Marshal(&struct {
		Alias
		ScrubbedValue string `json:"scrubbed_value"`
	}{
		Alias:         Alias(c),
		ScrubbedValue: c.Scrubbed(),
	})
}

// Apply attaches the credential to an outgoing HTTP request.
func (c Credential) Apply(req *http.Request) {
	switch c.Type {
	case CredTypeBearer:
		header := c.HeaderName
		if header == "" {
			header = "Authorization"
		}
		val := c.Value
		if !strings.HasPrefix(strings.ToLower(val), "bearer ") {
			val = "Bearer " + val
		}
		req.Header.Set(header, val)

	case CredTypeAPIKey:
		if c.QueryParam != "" {
			q := req.URL.Query()
			q.Set(c.QueryParam, c.Value)
			req.URL.RawQuery = q.Encode()
		} else {
			header := c.HeaderName
			if header == "" {
				header = "X-API-Key"
			}
			req.Header.Set(header, c.Value)
		}

	case CredTypeBasic:
		req.SetBasicAuth(c.Username, c.Password)

	case CredTypeCookie:
		cName := c.CookieName
		if cName == "" {
			cName = "session"
		}
		req.AddCookie(&http.Cookie{
			Name:  cName,
			Value: c.Value,
		})
	}
}

// AuthorizationRecord captures client certification details.
type AuthorizationRecord struct {
	ID                  string     `json:"id"`
	AuthorizingParty    string     `json:"authorizing_party"`
	AuthorizationMethod string     `json:"authorization_method"`
	Status              string     `json:"status"` // "APPROVED", "PENDING", "EXPIRED", "REVOKED"
	ValidFrom           *time.Time `json:"valid_from,omitempty"`
	ValidUntil          *time.Time `json:"valid_until,omitempty"`
}

// IsCurrentlyValid verifies if the authorization is APPROVED and active.
func (a *AuthorizationRecord) IsCurrentlyValid(now time.Time) (bool, string) {
	if a == nil {
		return false, "no authorization record exists"
	}
	if !strings.EqualFold(a.Status, "APPROVED") {
		return false, fmt.Sprintf("authorization status is %s (must be APPROVED)", a.Status)
	}
	if a.ValidFrom != nil && now.Before(*a.ValidFrom) {
		return false, fmt.Sprintf("authorization not yet active (valid from %s)", a.ValidFrom.Format(time.RFC3339))
	}
	if a.ValidUntil != nil && now.After(*a.ValidUntil) {
		return false, fmt.Sprintf("authorization expired on %s", a.ValidUntil.Format(time.RFC3339))
	}
	return true, ""
}

// VerificationConfig configures the authentication security verification engine.
type VerificationConfig struct {
	TargetURL               string
	Endpoints               []string
	PrimaryCredential       Credential
	ExpiredCredential       *Credential
	ExpectedProtectedRoutes []string
	PublicRoutes            []string
	MaxRequestsTotal        int
	MaxRequestsPerHost      int
	RateLimit               float64
	MaxConcurrency          int
	PerRequestTimeout       time.Duration
	OverallDeadline         time.Duration
	MaxResponseSize         int64
	MaxRedirects            int
	AllowLoopback           bool
	AllowPrivateIPs         bool
	DryRun                  bool
	CheckRateLimiting       bool
	Authorization           *AuthorizationRecord
	IsAllowed               func(string) bool
	IsExcluded              func(string) bool
	Resolver                *net.Resolver
}

// AuthTestResult records the outcome of an individual authentication check.
type AuthTestResult struct {
	ID                string            `json:"id"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	TestType          AuthTestType      `json:"test_type"`
	Disposition       AuthDisposition   `json:"disposition"`
	HTTPStatus        int               `json:"http_status"`
	BaselineStatus    int               `json:"baseline_status,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	Details           map[string]string `json:"details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	RequestDispatched bool              `json:"request_dispatched"`
	DurationMs        int64             `json:"duration_ms"`
	Timestamp         time.Time         `json:"timestamp"`
}

// VerificationSummary aggregates metrics across the verification run.
type VerificationSummary struct {
	TotalEndpoints    int   `json:"total_endpoints"`
	TotalRequests     int   `json:"total_requests"`
	TotalTested       int   `json:"total_tested"`
	TotalPassed       int   `json:"total_passed"`
	TotalWeaknesses   int   `json:"total_weaknesses"`
	TotalCandidates   int   `json:"total_candidates"`
	TotalSkipped      int   `json:"total_skipped"`
	TotalFailed       int   `json:"total_failed"`
	TotalInconclusive int   `json:"total_inconclusive"`
	TotalUnsupported  int   `json:"total_unsupported"`
	FindingsCount     int   `json:"findings_count"`
	DurationMs        int64 `json:"duration_ms"`
}

// VerificationReport contains the final results, findings, and metrics of an authentication verification run.
type VerificationReport struct {
	TargetURL       string              `json:"target_url"`
	Summary         VerificationSummary `json:"summary"`
	BudgetExhausted bool                `json:"budget_exhausted"`
	DryRun          bool                `json:"dry_run"`
	StartedAt       time.Time           `json:"started_at"`
	CompletedAt     time.Time           `json:"completed_at"`
	DurationMs      int64               `json:"duration_ms"`
	Results         []AuthTestResult    `json:"results"`
	Findings        []report.Finding    `json:"findings"`
	Limitations     []string            `json:"limitations,omitempty"`
}

// BudgetTracker manages thread-safe request counting against configured limits.
type BudgetTracker struct {
	mu          sync.Mutex
	maxTotal    int
	maxPerHost  int
	totalUsed   int
	usedPerHost map[string]int
	exhausted   bool
}

func newBudgetTracker(maxTotal, maxPerHost int) *BudgetTracker {
	if maxTotal <= 0 {
		maxTotal = 30
	}
	if maxPerHost <= 0 {
		maxPerHost = 15
	}
	return &BudgetTracker{
		maxTotal:    maxTotal,
		maxPerHost:  maxPerHost,
		usedPerHost: make(map[string]int),
	}
}

func (bt *BudgetTracker) TryAcquire(host string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	cleanHost := strings.ToLower(host)
	if bt.totalUsed >= bt.maxTotal {
		bt.exhausted = true
		return false
	}
	if bt.usedPerHost[cleanHost] >= bt.maxPerHost {
		return false
	}

	bt.totalUsed++
	bt.usedPerHost[cleanHost]++
	return true
}

func (bt *BudgetTracker) TotalSent() int {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return bt.totalUsed
}

func (bt *BudgetTracker) IsExhausted() bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return bt.exhausted || bt.totalUsed >= bt.maxTotal
}

// Verifier implements active authentication security verification.
type Verifier struct{}

// NewVerifier creates an authentication verifier instance.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// Verify conducts bounded, authorized authentication security verification.
func (v *Verifier) Verify(ctx context.Context, cfg VerificationConfig) (*VerificationReport, error) {
	startedAt := time.Now().UTC()

	// 1. Mandatory Authorization Gate
	if cfg.Authorization == nil {
		return nil, ErrMissingAuthorization
	}
	if valid, reason := cfg.Authorization.IsCurrentlyValid(startedAt); !valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAuthorization, reason)
	}

	// 2. Target Scope Validation
	targetURL := strings.TrimSpace(cfg.TargetURL)
	if targetURL == "" {
		return nil, errors.New("target URL is required")
	}
	parsedTarget, err := url.Parse(targetURL)
	if err != nil || parsedTarget.Host == "" {
		return nil, fmt.Errorf("invalid target URL %q", targetURL)
	}

	if cfg.IsExcluded != nil && cfg.IsExcluded(targetURL) {
		return nil, ErrTargetExcluded
	}
	if cfg.IsAllowed != nil && !cfg.IsAllowed(targetURL) {
		return nil, ErrTargetOutOfScope
	}

	// Apply default resource limits
	perReqTimeout := cfg.PerRequestTimeout
	if perReqTimeout <= 0 {
		perReqTimeout = 5 * time.Second
	}
	overallDeadline := cfg.OverallDeadline
	if overallDeadline <= 0 {
		overallDeadline = 30 * time.Second
	}
	maxRespSize := cfg.MaxResponseSize
	if maxRespSize <= 0 {
		maxRespSize = 512 * 1024
	}
	maxRedirects := cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	rateLimit := cfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = 10.0
	}
	maxConcurrency := cfg.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 2
	}

	runCtx, cancel := context.WithTimeout(ctx, overallDeadline)
	defer cancel()

	rep := &VerificationReport{
		TargetURL: secrets.SanitizeURL(targetURL),
		DryRun:    cfg.DryRun,
		StartedAt: startedAt,
		Results:   []AuthTestResult{},
		Findings:  []report.Finding{},
	}

	// Normalize target endpoints
	endpoints := cfg.Endpoints
	if len(endpoints) == 0 {
		endpoints = []string{targetURL}
	}

	rep.Summary.TotalEndpoints = len(endpoints)

	// Dry Run Mode: Plan checks without network dispatch
	if cfg.DryRun {
		for _, ep := range endpoints {
			cleanEP := secrets.SanitizeURL(ep)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanEP, "GET", TestEnforcementBaseline),
				Endpoint:          cleanEP,
				Method:            "GET",
				TestType:          TestEnforcementBaseline,
				Disposition:       DispositionSkipped,
				EvidenceSummary:   "Authorized and in scope; skipped during dry-run planning mode",
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalSkipped++
		}
		completedAt := time.Now().UTC()
		rep.CompletedAt = completedAt
		rep.DurationMs = time.Since(startedAt).Milliseconds()
		rep.Summary.DurationMs = rep.DurationMs
		return rep, nil
	}

	budgetTracker := newBudgetTracker(cfg.MaxRequestsTotal, cfg.MaxRequestsPerHost)

	// Construct Safe HTTP Transport & Client
	safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:         perReqTimeout,
		KeepAlive:       30 * time.Second,
		AllowLoopback:   cfg.AllowLoopback,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
		Resolver:        cfg.Resolver,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	})

	rateTransport := crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{
		Rate:           rateLimit,
		MaxConcurrency: maxConcurrency,
	})

	httpClient := &http.Client{
		Transport: rateTransport,
		Timeout:   perReqTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q blocked", req.URL.Scheme)
			}
			if req.URL.User != nil {
				return errors.New("redirect with embedded credentials blocked")
			}
			destHost := req.URL.Hostname()
			if ip := net.ParseIP(destHost); ip != nil {
				if prohibited, reason := crawler.ProhibitedIPReason(ip, cfg.AllowLoopback, cfg.AllowPrivateIPs); prohibited {
					return fmt.Errorf("redirect to prohibited IP %s blocked: %s", destHost, reason)
				}
			}
			nextURL := req.URL.String()
			if cfg.IsExcluded != nil && cfg.IsExcluded(nextURL) {
				return fmt.Errorf("redirect blocked: destination %s matches exclusion rule", nextURL)
			}
			if cfg.IsAllowed != nil && !cfg.IsAllowed(nextURL) {
				return fmt.Errorf("redirect blocked: destination %s is outside approved scope", nextURL)
			}

			// Cross-origin redirect defense: strip sensitive credentials across host/port authority boundaries
			if len(via) > 0 {
				prevHost := strings.ToLower(via[len(via)-1].URL.Host)
				currHost := strings.ToLower(req.URL.Host)
				if prevHost != "" && currHost != "" && prevHost != currHost {
					req.Header.Del("Authorization")
					req.Header.Del("Cookie")
					req.Header.Del("X-API-Key")
				}
			}
			return nil
		},
	}

	knownPublicSet := make(map[string]bool)
	for _, p := range cfg.PublicRoutes {
		knownPublicSet[normalizePath(p)] = true
	}

	expectedProtectedSet := make(map[string]bool)
	for _, p := range cfg.ExpectedProtectedRoutes {
		expectedProtectedSet[normalizePath(p)] = true
	}

	var (
		observedProtected   []string
		observedUnprotected []string
	)

	// Execute tests across endpoints
	for _, epRaw := range endpoints {
		if runCtx.Err() != nil {
			rep.Limitations = append(rep.Limitations, fmt.Sprintf("Assessment stopped: %v", runCtx.Err()))
			break
		}
		if budgetTracker.IsExhausted() {
			rep.BudgetExhausted = true
			rep.Limitations = append(rep.Limitations, "Global request budget limit reached")
			break
		}

		fullURL, err := resolveEndpointURL(targetURL, epRaw)
		if err != nil {
			continue
		}
		cleanURL := secrets.SanitizeURL(fullURL)

		// Scope enforcement on individual endpoint
		if cfg.IsExcluded != nil && cfg.IsExcluded(fullURL) {
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestEnforcementBaseline,
				Disposition:       DispositionSkipped,
				EvidenceSummary:   "Endpoint matches exclusion rule; zero requests dispatched",
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalSkipped++
			continue
		}
		if cfg.IsAllowed != nil && !cfg.IsAllowed(fullURL) {
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestEnforcementBaseline,
				Disposition:       DispositionSkipped,
				EvidenceSummary:   "Endpoint is outside approved scope; zero requests dispatched",
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalSkipped++
			continue
		}

		// Check for unsupported authentication schemes
		if cfg.PrimaryCredential.Type != "" &&
			cfg.PrimaryCredential.Type != CredTypeBearer &&
			cfg.PrimaryCredential.Type != CredTypeAPIKey &&
			cfg.PrimaryCredential.Type != CredTypeBasic &&
			cfg.PrimaryCredential.Type != CredTypeCookie {
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestUnsupported),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestUnsupported,
				Disposition:       DispositionUnsupported,
				EvidenceSummary:   fmt.Sprintf("Authentication scheme %q is unsupported for active verification", cfg.PrimaryCredential.Type),
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalUnsupported++
			rep.Summary.TotalTested++
			rep.Limitations = append(rep.Limitations, fmt.Sprintf("Authentication scheme %q is unsupported for active verification", cfg.PrimaryCredential.Type))
			continue
		}

		// Transport check: unencrypted HTTP (non-loopback destinations)
		if strings.HasPrefix(strings.ToLower(fullURL), "http://") && cfg.PrimaryCredential.Value != "" && !isLoopbackHost(parsedHost(fullURL)) {
			f := buildCleartextFinding(cleanURL, cfg.PrimaryCredential.Type)
			rep.Findings = append(rep.Findings, f)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestCleartextTransport),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestCleartextTransport,
				Disposition:       DispositionWeaknessVerified,
				HTTPStatus:        0,
				EvidenceSummary:   "Authentication credentials configured for transmission over cleartext HTTP",
				Finding:           &f,
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalWeaknesses++
		}

		// Query parameter credential check
		if hasSensitiveQueryToken(fullURL) {
			f := buildTokenInURLFinding(cleanURL)
			rep.Findings = append(rep.Findings, f)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestInformationLeakage),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestInformationLeakage,
				Disposition:       DispositionWeaknessVerified,
				EvidenceSummary:   "Authentication credential or API key transmitted in URL query parameter",
				Finding:           &f,
				RequestDispatched: false,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalWeaknesses++
		}

		epHost := parsedHost(fullURL)

		// -------------------------------------------------------------
		// Probe 1: Baseline Request (Unauthenticated)
		// -------------------------------------------------------------
		if !budgetTracker.TryAcquire(epHost) {
			rep.Limitations = append(rep.Limitations, fmt.Sprintf("Per-host budget reached for %s", epHost))
			break
		}

		baseReqStart := time.Now()
		baseResp, baseBody, baseErr := sendProbe(runCtx, httpClient, "GET", fullURL, nil, maxRespSize)
		baseDuration := time.Since(baseReqStart).Milliseconds()

		if baseErr != nil {
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestEnforcementBaseline,
				Disposition:       DispositionFailed,
				EvidenceSummary:   fmt.Sprintf("Baseline probe failed: %v", baseErr),
				RequestDispatched: true,
				DurationMs:        baseDuration,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalFailed++
			rep.Summary.TotalTested++
			continue
		}

		rep.Summary.TotalTested++

		// Check for excessive information leakage or stack trace in baseline error
		if isVerboseAuthError(baseResp.StatusCode, string(baseBody)) {
			f := buildVerboseErrorFinding(cleanURL, baseResp.StatusCode, string(baseBody))
			rep.Findings = append(rep.Findings, f)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestInformationLeakage),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestInformationLeakage,
				Disposition:       DispositionWeaknessVerified,
				HTTPStatus:        baseResp.StatusCode,
				EvidenceSummary:   "Excessively verbose authentication error message observed in response body",
				Finding:           &f,
				RequestDispatched: true,
				DurationMs:        baseDuration,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalWeaknesses++
		}

		// Check if response reflects credentials
		if cfg.PrimaryCredential.Value != "" && strings.Contains(string(baseBody), cfg.PrimaryCredential.Value) {
			f := buildCredentialEchoFinding(cleanURL)
			rep.Findings = append(rep.Findings, f)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestInformationLeakage),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestInformationLeakage,
				Disposition:       DispositionWeaknessVerified,
				HTTPStatus:        baseResp.StatusCode,
				EvidenceSummary:   "Server response body reflects authentication credentials",
				Finding:           &f,
				RequestDispatched: true,
				DurationMs:        baseDuration,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalWeaknesses++
		}

		// -------------------------------------------------------------
		// Probe 2: Authenticated Request (Controlled test credential)
		// -------------------------------------------------------------
		var (
			authResp *http.Response
			authBody []byte
			authErr  error
		)

		hasAuthCred := cfg.PrimaryCredential.Value != "" || (cfg.PrimaryCredential.Username != "" && cfg.PrimaryCredential.Password != "")
		if hasAuthCred && !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
			authResp, authBody, authErr = sendProbe(runCtx, httpClient, "GET", fullURL, &cfg.PrimaryCredential, maxRespSize)
		}

		epPathNorm := normalizePath(fullURL)
		isKnownPublic := knownPublicSet[epPathNorm] || isPublicPathHeuristic(epPathNorm)
		isExpectedProtected := expectedProtectedSet[epPathNorm]

		// -------------------------------------------------------------
		// Analyze Authentication Enforcement
		// -------------------------------------------------------------
		if baseResp.StatusCode == http.StatusUnauthorized || baseResp.StatusCode == http.StatusForbidden {
			observedProtected = append(observedProtected, cleanURL)
			// Endpoint correctly required authentication on unauthenticated request!
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestMissingCredential),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestMissingCredential,
				Disposition:       DispositionPassed,
				HTTPStatus:        baseResp.StatusCode,
				BaselineStatus:    baseResp.StatusCode,
				EvidenceSummary:   fmt.Sprintf("Endpoint correctly rejected unauthenticated request with HTTP %d", baseResp.StatusCode),
				RequestDispatched: true,
				DurationMs:        baseDuration,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalPassed++

			// ---------------------------------------------------------
			// Probe 3: Invalid Synthetic Credential Test
			// ---------------------------------------------------------
			if hasAuthCred && !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
				fakeCred := buildSyntheticInvalidCred(cfg.PrimaryCredential)
				invResp, invBody, invErr := sendProbe(runCtx, httpClient, "GET", fullURL, &fakeCred, maxRespSize)
				if invErr == nil {
					if invResp.StatusCode == http.StatusOK && hasMeaningfulApplicationPayload(invResp, invBody) {
						// Server accepted invalid synthetic token and returned application payload!
						f := buildInvalidAcceptedFinding(cleanURL, invResp.StatusCode)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestInvalidCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestInvalidCredential,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        invResp.StatusCode,
							BaselineStatus:    baseResp.StatusCode,
							EvidenceSummary:   "Endpoint granted application access on synthetic invalid token",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else if invResp.StatusCode == http.StatusInternalServerError {
						// Server crashed on invalid token
						f := buildMalformedCrashFinding(cleanURL)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestInvalidCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestInvalidCredential,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        invResp.StatusCode,
							BaselineStatus:    baseResp.StatusCode,
							EvidenceSummary:   "Server unhandled HTTP 500 error on synthetic invalid token",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else {
						// Server properly rejected invalid token!
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestInvalidCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestInvalidCredential,
							Disposition:       DispositionPassed,
							HTTPStatus:        invResp.StatusCode,
							BaselineStatus:    baseResp.StatusCode,
							EvidenceSummary:   fmt.Sprintf("Endpoint correctly rejected synthetic invalid credential with HTTP %d", invResp.StatusCode),
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalPassed++
					}
				}
			}

			// ---------------------------------------------------------
			// Probe 4: Malformed Header Test
			// ---------------------------------------------------------
			if hasAuthCred && !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
				malformedCred := buildMalformedHeaderCred(cfg.PrimaryCredential)
				malResp, _, malErr := sendProbe(runCtx, httpClient, "GET", fullURL, &malformedCred, maxRespSize)
				if malErr == nil {
					if malResp.StatusCode == http.StatusInternalServerError {
						f := buildMalformedCrashFinding(cleanURL)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestMalformedHeader),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestMalformedHeader,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        malResp.StatusCode,
							EvidenceSummary:   "Server unhandled HTTP 500 error on syntactically malformed authorization header",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else {
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestMalformedHeader),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestMalformedHeader,
							Disposition:       DispositionPassed,
							HTTPStatus:        malResp.StatusCode,
							EvidenceSummary:   fmt.Sprintf("Endpoint handled malformed header safely with HTTP %d", malResp.StatusCode),
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalPassed++
					}
				}
			}

			// ---------------------------------------------------------
			// Probe 5: Empty Credential Value Test
			// ---------------------------------------------------------
			if hasAuthCred && !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
				emptyCred := buildEmptyValueCred(cfg.PrimaryCredential)
				empResp, empBody, empErr := sendProbe(runCtx, httpClient, "GET", fullURL, &emptyCred, maxRespSize)
				if empErr == nil {
					if empResp.StatusCode == http.StatusOK && hasMeaningfulApplicationPayload(empResp, empBody) {
						f := buildInvalidAcceptedFinding(cleanURL, empResp.StatusCode)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestEmptyCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestEmptyCredential,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        empResp.StatusCode,
							EvidenceSummary:   "Endpoint granted application access on empty credential token",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else {
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestEmptyCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestEmptyCredential,
							Disposition:       DispositionPassed,
							HTTPStatus:        empResp.StatusCode,
							EvidenceSummary:   fmt.Sprintf("Endpoint correctly rejected empty credential value with HTTP %d", empResp.StatusCode),
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalPassed++
					}
				}
			}

			// ---------------------------------------------------------
			// Probe 6: Expired Synthetic Credential Test (if supplied)
			// ---------------------------------------------------------
			if cfg.ExpiredCredential != nil && !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
				expResp, expBody, expErr := sendProbe(runCtx, httpClient, "GET", fullURL, cfg.ExpiredCredential, maxRespSize)
				if expErr == nil {
					if expResp.StatusCode == http.StatusOK && hasMeaningfulApplicationPayload(expResp, expBody) {
						f := buildExpiredAcceptedFinding(cleanURL)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestExpiredCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestExpiredCredential,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        expResp.StatusCode,
							EvidenceSummary:   "Server accepted expired test credential with HTTP 200",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else {
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestExpiredCredential),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestExpiredCredential,
							Disposition:       DispositionPassed,
							HTTPStatus:        expResp.StatusCode,
							EvidenceSummary:   fmt.Sprintf("Server correctly rejected expired test credential with HTTP %d", expResp.StatusCode),
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalPassed++
					}
				}
			}

			// ---------------------------------------------------------
			// Probe 7: Method Bypass Test (HEAD method without auth)
			// ---------------------------------------------------------
			if !budgetTracker.IsExhausted() && budgetTracker.TryAcquire(epHost) {
				headResp, _, headErr := sendProbe(runCtx, httpClient, "HEAD", fullURL, nil, maxRespSize)
				if headErr == nil {
					if headResp.StatusCode == http.StatusOK {
						f := buildMethodBypassFinding(cleanURL, "HEAD")
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "HEAD", TestMethodBypass),
							Endpoint:          cleanURL,
							Method:            "HEAD",
							TestType:          TestMethodBypass,
							Disposition:       DispositionWeaknessVerified,
							HTTPStatus:        headResp.StatusCode,
							BaselineStatus:    baseResp.StatusCode,
							EvidenceSummary:   "Authentication enforced on GET but bypassed via HEAD returning HTTP 200",
							Finding:           &f,
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalWeaknesses++
					} else {
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "HEAD", TestMethodBypass),
							Endpoint:          cleanURL,
							Method:            "HEAD",
							TestType:          TestMethodBypass,
							Disposition:       DispositionPassed,
							HTTPStatus:        headResp.StatusCode,
							EvidenceSummary:   fmt.Sprintf("HEAD method rejected unauthenticated access with HTTP %d", headResp.StatusCode),
							RequestDispatched: true,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalPassed++
					}
				}
			}

		} else if baseResp.StatusCode == http.StatusOK {
			if !isKnownPublic {
				observedUnprotected = append(observedUnprotected, cleanURL)
			}
			// Unauthenticated request returned HTTP 200 OK!
			if isKnownPublic {
				// Expected public endpoint
				rep.Results = append(rep.Results, AuthTestResult{
					ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
					Endpoint:          cleanURL,
					Method:            "GET",
					TestType:          TestEnforcementBaseline,
					Disposition:       DispositionPassed,
					HTTPStatus:        baseResp.StatusCode,
					EvidenceSummary:   "Public endpoint returned HTTP 200 OK without authentication (normal behavior)",
					RequestDispatched: true,
					DurationMs:        baseDuration,
					Timestamp:         time.Now().UTC(),
				})
				rep.Summary.TotalPassed++
			} else if isExpectedProtected {
				// Explicitly expected to be protected, but returned 200 OK without authentication!
				if hasMeaningfulApplicationPayload(baseResp, baseBody) {
					f := buildMissingAuthFinding(cleanURL, baseResp.StatusCode, true)
					rep.Findings = append(rep.Findings, f)
					rep.Results = append(rep.Results, AuthTestResult{
						ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
						Endpoint:          cleanURL,
						Method:            "GET",
						TestType:          TestEnforcementBaseline,
						Disposition:       DispositionWeaknessVerified,
						HTTPStatus:        baseResp.StatusCode,
						EvidenceSummary:   "Protected route returned sensitive application payload without authentication",
						Finding:           &f,
						RequestDispatched: true,
						DurationMs:        baseDuration,
						Timestamp:         time.Now().UTC(),
					})
					rep.Summary.TotalWeaknesses++
				} else {
					rep.Results = append(rep.Results, AuthTestResult{
						ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
						Endpoint:          cleanURL,
						Method:            "GET",
						TestType:          TestEnforcementBaseline,
						Disposition:       DispositionInconclusive,
						HTTPStatus:        baseResp.StatusCode,
						EvidenceSummary:   "Protected route returned HTTP 200 OK but payload does not indicate application data",
						RequestDispatched: true,
						DurationMs:        baseDuration,
						Timestamp:         time.Now().UTC(),
					})
					rep.Summary.TotalInconclusive++
				}
			} else {
				// Policy unknown: compare against authenticated probe if available
				if authResp != nil && authErr == nil && authResp.StatusCode == http.StatusOK {
					if responsesSemanticallyEquivalent(baseResp, baseBody, authResp, authBody) && hasMeaningfulApplicationPayload(baseResp, baseBody) {
						// Identical application payload served with or without credentials
						f := buildMissingAuthFinding(cleanURL, baseResp.StatusCode, false)
						rep.Findings = append(rep.Findings, f)
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestEnforcementBaseline,
							Disposition:       DispositionCandidate,
							HTTPStatus:        baseResp.StatusCode,
							BaselineStatus:    authResp.StatusCode,
							EvidenceSummary:   "Endpoint returns identical application payload with or without credentials; candidate unauthenticated exposure",
							Finding:           &f,
							RequestDispatched: true,
							DurationMs:        baseDuration,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalCandidates++
					} else {
						// Different responses without clear exposure proof
						rep.Results = append(rep.Results, AuthTestResult{
							ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
							Endpoint:          cleanURL,
							Method:            "GET",
							TestType:          TestEnforcementBaseline,
							Disposition:       DispositionInconclusive,
							HTTPStatus:        baseResp.StatusCode,
							EvidenceSummary:   "Endpoint accepts unauthenticated requests with HTTP 200; policy unknown and payload difference inconclusive",
							RequestDispatched: true,
							DurationMs:        baseDuration,
							Timestamp:         time.Now().UTC(),
						})
						rep.Summary.TotalInconclusive++
					}
				} else {
					// Single unauthenticated 200 without known policy
					rep.Results = append(rep.Results, AuthTestResult{
						ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
						Endpoint:          cleanURL,
						Method:            "GET",
						TestType:          TestEnforcementBaseline,
						Disposition:       DispositionInconclusive,
						HTTPStatus:        baseResp.StatusCode,
						EvidenceSummary:   "Endpoint returned HTTP 200 OK; policy unknown; classified as inconclusive observation",
						RequestDispatched: true,
						DurationMs:        baseDuration,
						Timestamp:         time.Now().UTC(),
					})
					rep.Summary.TotalInconclusive++
				}
			}
		} else {
			// Status other than 200, 401, 403 (e.g. 404, 301, 500)
			rep.Results = append(rep.Results, AuthTestResult{
				ID:                computeResultID(cleanURL, "GET", TestEnforcementBaseline),
				Endpoint:          cleanURL,
				Method:            "GET",
				TestType:          TestEnforcementBaseline,
				Disposition:       DispositionInconclusive,
				HTTPStatus:        baseResp.StatusCode,
				EvidenceSummary:   fmt.Sprintf("Endpoint returned HTTP %d on baseline probe; inconclusive authentication evidence", baseResp.StatusCode),
				RequestDispatched: true,
				DurationMs:        baseDuration,
				Timestamp:         time.Now().UTC(),
			})
			rep.Summary.TotalInconclusive++
		}

		// -------------------------------------------------------------
		// Probe 8: Bounded Rate Limiting Check (if explicitly enabled)
		// -------------------------------------------------------------
		if cfg.CheckRateLimiting && isAuthOrLoginRoute(epPathNorm) {
			rateLimited := false
			maxProbes := 5
			probeCount := 0

			for i := 0; i < maxProbes; i++ {
				if runCtx.Err() != nil || budgetTracker.IsExhausted() {
					break
				}
				if !budgetTracker.TryAcquire(epHost) {
					break
				}
				probeCount++
				fakeUserCred := Credential{
					Type:     CredTypeBasic,
					Username: fmt.Sprintf("felix_synth_user_%d", i),
					Password: fmt.Sprintf("invalid_pass_%d", i),
				}
				rlResp, _, rlErr := sendProbe(runCtx, httpClient, "GET", fullURL, &fakeUserCred, maxRespSize)
				if rlErr == nil {
					if rlResp.StatusCode == http.StatusTooManyRequests || rlResp.Header.Get("Retry-After") != "" || rlResp.Header.Get("X-RateLimit-Remaining") == "0" {
						rateLimited = true
						break
					}
				}
			}

			if rateLimited {
				rep.Results = append(rep.Results, AuthTestResult{
					ID:                computeResultID(cleanURL, "GET", TestRateLimiting),
					Endpoint:          cleanURL,
					Method:            "GET",
					TestType:          TestRateLimiting,
					Disposition:       DispositionPassed,
					HTTPStatus:        http.StatusTooManyRequests,
					EvidenceSummary:   "Authentication endpoint enforces active rate limiting on repeated invalid attempts",
					RequestDispatched: true,
					Timestamp:         time.Now().UTC(),
				})
				rep.Summary.TotalPassed++
			} else {
				// Conservative conclusion: 5 probes is not enough to conclude lack of rate limiting
				rep.Results = append(rep.Results, AuthTestResult{
					ID:                computeResultID(cleanURL, "GET", TestRateLimiting),
					Endpoint:          cleanURL,
					Method:            "GET",
					TestType:          TestRateLimiting,
					Disposition:       DispositionInconclusive,
					EvidenceSummary:   fmt.Sprintf("No rate limiting triggered within safe %d-probe budget; rate limit threshold may exceed test budget", probeCount),
					RequestDispatched: true,
					Timestamp:         time.Now().UTC(),
				})
				rep.Summary.TotalInconclusive++
			}
		}
	}

	// Inconsistent Route Analysis across related routes
	if len(observedProtected) > 0 && len(observedUnprotected) > 0 {
		for _, unprot := range observedUnprotected {
			for _, prot := range observedProtected {
				if shareRoutePrefix(unprot, prot) {
					f := buildRouteInconsistencyFinding(unprot, prot)
					rep.Findings = append(rep.Findings, f)
					rep.Results = append(rep.Results, AuthTestResult{
						ID:                computeResultID(unprot, "GET", TestInconsistentRoute),
						Endpoint:          unprot,
						Method:            "GET",
						TestType:          TestInconsistentRoute,
						Disposition:       DispositionCandidate,
						HTTPStatus:        200,
						EvidenceSummary:   fmt.Sprintf("Inconsistent authentication: %s requires authentication but related route %s is accessible without credentials", prot, unprot),
						Finding:           &f,
						RequestDispatched: false,
						Timestamp:         time.Now().UTC(),
					})
					rep.Summary.TotalCandidates++
					break
				}
			}
		}
	} else if len(observedProtected) > 1 && len(observedUnprotected) == 0 {
		rep.Results = append(rep.Results, AuthTestResult{
			ID:                computeResultID(rep.TargetURL, "GET", TestInconsistentRoute),
			Endpoint:          rep.TargetURL,
			Method:            "GET",
			TestType:          TestInconsistentRoute,
			Disposition:       DispositionPassed,
			EvidenceSummary:   "Consistent authentication enforcement observed across all discovered sibling routes",
			RequestDispatched: false,
			Timestamp:         time.Now().UTC(),
		})
		rep.Summary.TotalPassed++
	}

	rep.Limitations = append(rep.Limitations, "External HTTP verification cannot validate server-side JWT signature cryptographic algorithms, key rotation, or revocation without verification keys or public JWKS endpoints")

	rep.Summary.TotalRequests = budgetTracker.TotalSent()
	rep.Summary.FindingsCount = len(rep.Findings)

	// Deterministic sorting of results and findings
	sort.Slice(rep.Results, func(i, j int) bool {
		if rep.Results[i].Endpoint != rep.Results[j].Endpoint {
			return rep.Results[i].Endpoint < rep.Results[j].Endpoint
		}
		if rep.Results[i].Method != rep.Results[j].Method {
			return rep.Results[i].Method < rep.Results[j].Method
		}
		return rep.Results[i].TestType < rep.Results[j].TestType
	})

	sort.Slice(rep.Findings, func(i, j int) bool {
		rI := severityRank(rep.Findings[i].Severity)
		rJ := severityRank(rep.Findings[j].Severity)
		if rI != rJ {
			return rI < rJ
		}
		if rep.Findings[i].Title != rep.Findings[j].Title {
			return rep.Findings[i].Title < rep.Findings[j].Title
		}
		return rep.Findings[i].ID < rep.Findings[j].ID
	})

	completedAt := time.Now().UTC()
	rep.CompletedAt = completedAt
	rep.DurationMs = time.Since(startedAt).Milliseconds()
	rep.Summary.DurationMs = rep.DurationMs

	return rep, nil
}

// ---------------------------------------------------------------------
// Helper Functions for Request Dispatch, Finding Building & Heuristics
// ---------------------------------------------------------------------

func sendProbe(ctx context.Context, client *http.Client, method, targetURL string, cred *Credential, maxBodySize int64) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Felix-Security-Auditor/1.0 (Authorized Testing)")
	req.Header.Set("Accept", "application/json, text/html, */*")

	if cred != nil {
		cred.Apply(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return resp, bodyBytes, nil
}

func computeResultID(endpoint, method string, testType AuthTestType) string {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte(method))
	h.Write([]byte(string(testType)))
	return fmt.Sprintf("auth-%s-%s", strings.ToLower(string(testType)), hex.EncodeToString(h.Sum(nil))[:8])
}

func resolveEndpointURL(baseURL, endpoint string) (string, error) {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint, nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}

func normalizePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return strings.ToLower(strings.TrimRight(p, "/"))
}

func parsedHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	return strings.ToLower(u.Host)
}

func isLoopbackHost(host string) bool {
	h := host
	if strings.Contains(h, ":") {
		if hostPart, _, err := net.SplitHostPort(h); err == nil {
			h = hostPart
		}
	}
	hLower := strings.ToLower(h)
	if hLower == "localhost" || hLower == "127.0.0.1" || hLower == "::1" || strings.HasPrefix(hLower, "127.") {
		return true
	}
	return false
}

func isPublicPathHeuristic(path string) bool {
	p := strings.ToLower(path)
	if p == "" || p == "/" || p == "/health" || p == "/healthz" || p == "/status" ||
		p == "/robots.txt" || p == "/favicon.ico" || strings.HasPrefix(p, "/static") ||
		strings.HasPrefix(p, "/assets") || strings.HasPrefix(p, "/public") ||
		strings.Contains(p, "login") || strings.Contains(p, "signin") ||
		strings.Contains(p, "register") || strings.Contains(p, "signup") {
		return true
	}
	return false
}

func isAuthOrLoginRoute(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "login") || strings.Contains(p, "signin") ||
		strings.Contains(p, "auth") || strings.Contains(p, "token") ||
		strings.Contains(p, "session")
}

func hasSensitiveQueryToken(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for k := range u.Query() {
		kLower := strings.ToLower(k)
		if kLower == "token" || kLower == "api_key" || kLower == "apikey" ||
			kLower == "access_token" || kLower == "secret" || kLower == "auth_token" ||
			kLower == "password" {
			return true
		}
	}
	return false
}

func hasMeaningfulApplicationPayload(resp *http.Response, body []byte) bool {
	if resp == nil || len(body) == 0 {
		return false
	}
	cType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(cType, "application/json") || strings.Contains(cType, "application/xml") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if (bytes.HasPrefix(trimmed, []byte("{")) && bytes.HasSuffix(trimmed, []byte("}"))) ||
		(bytes.HasPrefix(trimmed, []byte("[")) && bytes.HasSuffix(trimmed, []byte("]"))) {
		return true
	}
	s := strings.ToLower(string(body))
	if strings.Contains(s, "\"email\":") || strings.Contains(s, "\"id\":") ||
		strings.Contains(s, "\"username\":") || strings.Contains(s, "\"user_id\":") ||
		strings.Contains(s, "\"balance\":") || strings.Contains(s, "\"role\":") {
		return true
	}
	return false
}

func responsesSemanticallyEquivalent(r1 *http.Response, b1 []byte, r2 *http.Response, b2 []byte) bool {
	if r1.StatusCode != r2.StatusCode {
		return false
	}
	if len(b1) == len(b2) && bytes.Equal(b1, b2) {
		return true
	}
	diff := len(b1) - len(b2)
	if diff < 0 {
		diff = -diff
	}
	// Within 5% size tolerance on non-empty bodies
	if len(b1) > 0 && float64(diff)/float64(len(b1)) < 0.05 {
		return true
	}
	return false
}

var (
	sqlSyntaxRegex  = regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|ora-[0-9]{5}|sqlite3::|postgresql.*error)`)
	stackTraceRegex = regexp.MustCompile(`(?i)(Traceback \(most recent call last\):|at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_]+\.java:[0-9]+\)|panic: runtime error:)`)
)

func isVerboseAuthError(statusCode int, body string) bool {
	if statusCode != 400 && statusCode != 401 && statusCode != 403 && statusCode != 500 {
		return false
	}
	if sqlSyntaxRegex.MatchString(body) || stackTraceRegex.MatchString(body) {
		return true
	}
	return false
}

func buildSyntheticInvalidCred(orig Credential) Credential {
	inv := orig
	inv.Value = "felix_synthetic_invalid_token_xyz987654321"
	inv.Password = "felix_invalid_password_synthetic"
	return inv
}

func buildMalformedHeaderCred(orig Credential) Credential {
	mal := orig
	mal.Value = "!!!malformed#header$format%invalid^tokens!!!"
	return mal
}

func buildEmptyValueCred(orig Credential) Credential {
	emp := orig
	emp.Value = ""
	emp.Password = ""
	return emp
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case report.SeverityCritical:
		return 1
	case report.SeverityHigh:
		return 2
	case report.SeverityMedium:
		return 3
	case report.SeverityLow:
		return 4
	default:
		return 5
	}
}

// ---------------------------------------------------------------------
// Finding Factory Methods adhering to FELIX conventions
// ---------------------------------------------------------------------

func shareRoutePrefix(u1, u2 string) bool {
	p1, err1 := url.Parse(u1)
	p2, err2 := url.Parse(u2)
	if err1 != nil || err2 != nil {
		return false
	}
	if !strings.EqualFold(p1.Host, p2.Host) {
		return false
	}
	path1 := strings.Trim(strings.ToLower(p1.Path), "/")
	path2 := strings.Trim(strings.ToLower(p2.Path), "/")
	if path1 == "" || path2 == "" {
		return false
	}
	parts1 := strings.Split(path1, "/")
	parts2 := strings.Split(path2, "/")
	common := 0
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		if parts1[i] == parts2[i] {
			common++
		} else {
			break
		}
	}
	return common >= 2 || (common >= 1 && (len(parts1) == 1 || len(parts2) == 1))
}

func buildRouteInconsistencyFinding(endpoint, protectedSibling string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte(protectedSibling))
	h.Write([]byte("AUTH-ROUTE-INCONSISTENCY"))
	fID := fmt.Sprintf("auth-inconsist-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-ROUTE-INCONSISTENCY",
		Status:                report.FindingStatusSuspected,
		ClassificationOutcome: report.OutcomeSuspected,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Route Consistency",
		Title:                 "Inconsistent Authentication Enforcement Across Related Routes",
		Severity:              report.SeverityMedium,
		Confidence:            report.ConfidenceMedium,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           fmt.Sprintf("Route %s is accessible unauthenticated while related sibling route %s enforces authentication.", endpoint, protectedSibling),
		Evidence:              fmt.Sprintf("Sibling route %s returned 401/403 requiring authentication, but related route %s returned HTTP 200 without authentication", protectedSibling, endpoint),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     fmt.Sprintf("Inconsistent auth policy between %s and %s", endpoint, protectedSibling),
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Ensure authentication middleware is applied systematically across all routes under the same prefix or resource grouping.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Apply route-wide authentication middleware uniformly.",
		},
		Source: "auth",
	}
}

func buildMissingAuthFinding(endpoint string, statusCode int, confirmed bool) report.Finding {
	status := report.FindingStatusSuspected
	severity := report.SeverityHigh
	confidence := report.ConfidenceMedium
	if confirmed {
		status = report.FindingStatusConfirmed
		confidence = report.ConfidenceHigh
	}

	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-ENFORCE-MISSING"))
	fID := fmt.Sprintf("auth-enforce-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-ENFORCE-MISSING",
		Status:                status,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Enforcement",
		Title:                 "Protected Endpoint Accessible Without Authentication",
		Severity:              severity,
		Confidence:            confidence,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "The endpoint returned HTTP 200 OK with application payload when accessed without authentication credentials.",
		Evidence:              fmt.Sprintf("Endpoint accepted unauthenticated GET request returning HTTP %d with sensitive application payload", statusCode),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     fmt.Sprintf("HTTP %d OK returned without credentials", statusCode),
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Ensure all sensitive and protected application routes enforce authentication middleware before serving requests. Reject unauthenticated access with HTTP 401 Unauthorized.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Require valid authentication credentials for all non-public application endpoints.",
		},
		Source: "auth",
	}
}

func buildInvalidAcceptedFinding(endpoint string, statusCode int) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-CRED-INVALID-ACCEPTED"))
	fID := fmt.Sprintf("auth-inv-accept-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-CRED-INVALID-ACCEPTED",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Credential Validation",
		Title:                 "Endpoint Accepts Invalid or Synthetic Credentials",
		Severity:              report.SeverityCritical,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "The server granted application access when presented with a synthetic invalid or empty credential token.",
		Evidence:              fmt.Sprintf("Server returned HTTP %d with application payload on invalid synthetic token", statusCode),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     fmt.Sprintf("HTTP %d OK granted on invalid token", statusCode),
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Validate authentication tokens and credentials server-side against cryptographic signatures, session stores, or identity providers. Never grant access on unverified or malformed credentials.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Implement strict server-side token signature and validity verification.",
		},
		Source: "auth",
	}
}

func buildMalformedCrashFinding(endpoint string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-CRED-MALFORMED-CRASH"))
	fID := fmt.Sprintf("auth-crash-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-CRED-MALFORMED-CRASH",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Exception Handling",
		Title:                 "Server Error (HTTP 500) on Malformed Authentication Header",
		Severity:              report.SeverityMedium,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "The server crashed with an unhandled HTTP 500 Internal Server Error when processing a syntactically malformed authorization header.",
		Evidence:              "Server responded with HTTP 500 Internal Server Error on malformed header value",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "HTTP 500 Internal Server Error observed on malformed header",
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Catch authentication parsing and decoding exceptions gracefully. Return HTTP 400 Bad Request or HTTP 401 Unauthorized instead of an unhandled HTTP 500 Internal Server Error.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Implement robust error handling around authorization header parsing.",
		},
		Source: "auth",
	}
}

func buildExpiredAcceptedFinding(endpoint string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-TOKEN-EXPIRED-ACCEPTED"))
	fID := fmt.Sprintf("auth-exp-accept-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-TOKEN-EXPIRED-ACCEPTED",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Token Validation",
		Title:                 "Expired Authentication Token Accepted by Server",
		Severity:              report.SeverityHigh,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "The endpoint accepted an expired authentication token without verifying its validity period.",
		Evidence:              "Server responded with HTTP 200 OK when presented with an expired test token",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Expired token accepted with HTTP 200 OK",
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Enforce token expiration claims ('exp') and reject expired tokens with HTTP 401 Unauthorized.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Enforce expiration claims and validity checks on all authentication tokens.",
		},
		Source: "auth",
	}
}

func buildMethodBypassFinding(endpoint, bypassMethod string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte(bypassMethod))
	h.Write([]byte("AUTH-METHOD-BYPASS"))
	fID := fmt.Sprintf("auth-bypass-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-METHOD-BYPASS",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Method Enforcement",
		Title:                 "Authentication Bypass via Alternative HTTP Method",
		Severity:              report.SeverityHigh,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                bypassMethod,
		Description:           fmt.Sprintf("Authentication is enforced for GET requests, but unauthenticated access is permitted via the %s HTTP method.", bypassMethod),
		Evidence:              fmt.Sprintf("Endpoint returned HTTP 401 on GET, but returned HTTP 200 on %s without credentials", bypassMethod),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     fmt.Sprintf("Bypass achieved via %s method", bypassMethod),
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Enforce authentication consistently across all supported HTTP verbs. Apply authentication filters to the entire route pattern regardless of method.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Apply authentication middleware globally across all HTTP verbs.",
		},
		Source: "auth",
	}
}

func buildCleartextFinding(endpoint string, credType CredentialType) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-CLEARTEXT-TRANSPORT"))
	fID := fmt.Sprintf("auth-cleartext-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-CLEARTEXT-TRANSPORT",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Transport Security",
		Title:                 "Authentication Credential Transmitted Over Unencrypted HTTP",
		Severity:              report.SeverityMedium,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           fmt.Sprintf("Authentication credentials of type %q are transmitted over cleartext HTTP without transport encryption.", credType),
		Evidence:              "Endpoint URL scheme is unencrypted http://; credentials exposed to network eavesdropping",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Unencrypted HTTP URL scheme",
			Location:        endpoint,
			DetectionMethod: "transport_security_analysis",
		},
		Remediation: "Enforce HTTPS for all authentication and API endpoints. Enable HTTP Strict Transport Security (HSTS) and reject cleartext HTTP requests.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Enforce TLS 1.2+ encryption on all authentication endpoints.",
		},
		Source: "auth",
	}
}

func buildTokenInURLFinding(endpoint string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-TOKEN-IN-URL"))
	fID := fmt.Sprintf("auth-url-tok-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-TOKEN-IN-URL",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Credential Transport",
		Title:                 "Authentication Credential Transmitted in URL Query Parameter",
		Severity:              report.SeverityMedium,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "Authentication tokens or API keys passed via URL query parameters leak into server logs, browser histories, and Referer headers.",
		Evidence:              "Sensitive authentication parameter identified in URL query string",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Query string credential detected",
			Location:        endpoint,
			DetectionMethod: "url_parameter_analysis",
		},
		Remediation: "Avoid passing tokens, passwords, or API keys in URL query parameters. Transmit credentials in standard HTTP headers (e.g. Authorization or X-API-Key).",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Relocate authentication credentials from URL query strings to HTTP request headers.",
		},
		Source: "auth",
	}
}

func buildCredentialEchoFinding(endpoint string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-LEAK-IN-RESPONSE"))
	fID := fmt.Sprintf("auth-leak-%s", hex.EncodeToString(h.Sum(nil))[:8])

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-LEAK-IN-RESPONSE",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Information Leakage",
		Title:                 "Authentication Token or Credential Disclosed in Response",
		Severity:              report.SeverityHigh,
		Confidence:            report.ConfidenceHigh,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "The server response body reflected or echoed authentication credentials, exposing sensitive identity tokens to interception.",
		Evidence:              "Server response body contains sensitive authentication credential value: [REDACTED]",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Credential value echoed in response body",
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Prevent reflection or echo of bearer tokens, passwords, or API keys in response bodies or headers.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Sanitize responses to prevent reflection of authentication credentials.",
		},
		Source: "auth",
	}
}

func buildVerboseErrorFinding(endpoint string, statusCode int, bodySnippet string) report.Finding {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte("AUTH-VERBOSE-ERROR"))
	fID := fmt.Sprintf("auth-verbose-%s", hex.EncodeToString(h.Sum(nil))[:8])

	cleanBody := secrets.RedactText(bodySnippet)
	cleanBody = html.EscapeString(cleanBody)
	if len(cleanBody) > 200 {
		cleanBody = cleanBody[:200] + "..."
	}

	return report.Finding{
		ID:                    fID,
		RuleID:                "AUTH-VERBOSE-ERROR",
		Status:                report.FindingStatusConfirmed,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodActive,
		Category:              "Authentication / Information Leakage",
		Title:                 "Excessively Verbose Authentication Error Message",
		Severity:              report.SeverityLow,
		Confidence:            report.ConfidenceMedium,
		Target:                endpoint,
		Endpoint:              endpoint,
		Method:                "GET",
		Description:           "Authentication error response exposes technical implementation details (e.g. database syntax, stack traces, or internal exceptions).",
		Evidence:              fmt.Sprintf("HTTP %d error response contained verbose technical diagnostic: %s", statusCode, cleanBody),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Technical exception snippet observed in error response",
			Location:        endpoint,
			DetectionMethod: "active_auth_verification",
		},
		Remediation: "Use generic authentication error messages (e.g. 'Invalid credentials') and disable verbose debug stack traces in production environments.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary: "Standardize error handling to emit generic, non-disclosing error messages.",
		},
		Source: "auth",
	}
}
