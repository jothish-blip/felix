package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// Common authorization validation matrix errors.
var (
	ErrOriginNotAllowed                 = errors.New("origin is not in approved local target scope")
	ErrNonLoopbackResolved              = errors.New("security violation: target resolved to non-loopback IP")
	ErrDNSResolutionEmpty               = errors.New("target host could not be resolved to any IP")
	ErrSocketDestinationEscaped         = errors.New("security violation: remote socket address is not loopback")
	ErrEndpointNotApprovedForOrigin     = errors.New("endpoint is not approved for this origin and method")
	ErrPathTraversalDetected            = errors.New("security violation: path traversal sequence detected")
	ErrRedirectDestinationUnauthorized  = errors.New("redirect destination violates origin or endpoint approval policy")
	ErrMutationsForbiddenOnLiveTarget   = errors.New("security policy: mutations are permanently forbidden on live targets")
	ErrAdminBaselineFailed              = errors.New("administrative baseline failed: cannot verify function authorization")
	ErrResourceOwnerRequired            = errors.New("resource owner persona ID is required")
	ErrAssessorRequired                 = errors.New("assessor persona ID is required")
)

// AuthzCategory represents the access control evaluation scope.
type AuthzCategory string

const (
	CategoryBOLA AuthzCategory = "BOLA" // Broken Object Level Authorization (OWASP API1:2023)
	CategoryIDOR AuthzCategory = "IDOR" // Insecure Direct Object Reference (CWE-639)
	CategoryBFLA AuthzCategory = "BFLA" // Broken Function Level Authorization (OWASP API5:2023)
)

// AuthzStatus represents the verified outcome of an access control evaluation.
type AuthzStatus string

const (
	StatusVerifiedDefect AuthzStatus = "VERIFIED_DEFECT" // Defect confirmed with positive baseline + probe proof
	StatusDefended       AuthzStatus = "DEFENDED_BARRIER" // Defended boundary confirmed with positive baseline + explicit refusal
	StatusInconclusive   AuthzStatus = "INCONCLUSIVE"    // Ambiguous response, missing baseline, or error payload
	StatusPublicResource AuthzStatus = "PUBLIC_RESOURCE" // Verified public endpoint accessible across all identities
)

// FixtureClassification categorizes the execution environment.
type FixtureClassification string

const (
	ClassSyntheticControlled FixtureClassification = "SYNTHETIC_CONTROLLED_FIXTURE"
	ClassLiveBenchmark       FixtureClassification = "LIVE_BENCHMARK_TARGET"
)

// TrustedTargetRecord defines the immutable safety boundaries for an origin.
type TrustedTargetRecord struct {
	FixtureID       string                `json:"fixture_id"`
	ExactOrigin     string                `json:"exact_origin"`
	Classification  FixtureClassification `json:"classification"`
	MutationAllowed bool                  `json:"mutation_allowed"`
}

// TrustedFixtureRegistry manages approved testing targets with engine-controlled boundaries.
type TrustedFixtureRegistry struct {
	mu      sync.RWMutex
	targets map[string]TrustedTargetRecord
}

// NewTrustedFixtureRegistry creates a registry pre-seeded with permanently read-only live targets.
func NewTrustedFixtureRegistry() *TrustedFixtureRegistry {
	r := &TrustedFixtureRegistry{
		targets: make(map[string]TrustedTargetRecord),
	}

	// Permanent read-only registration for live targets
	liveTargets := []string{
		"http://127.0.0.1:5000",
		"http://localhost:5000",
		"http://127.0.0.1:4000",
		"http://localhost:4000",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
	}

	for _, orig := range liveTargets {
		r.targets[orig] = TrustedTargetRecord{
			FixtureID:       "live-benchmark-" + orig,
			ExactOrigin:     orig,
			Classification:  ClassLiveBenchmark,
			MutationAllowed: false, // Permanently false
		}
	}

	return r
}

// RegisterTarget registers a target origin in the trusted fixture registry.
func (r *TrustedFixtureRegistry) RegisterTarget(rec TrustedTargetRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Enforce immutable live benchmark safety: live origins can NEVER have MutationAllowed true or be reclassified
	if existing, exists := r.targets[rec.ExactOrigin]; exists && existing.Classification == ClassLiveBenchmark {
		return
	}
	if rec.Classification == ClassLiveBenchmark {
		rec.MutationAllowed = false
	}
	r.targets[rec.ExactOrigin] = rec
}

// IsMutationAllowed checks whether state-changing mutations are permitted for an origin.
func (r *TrustedFixtureRegistry) IsMutationAllowed(origin string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.targets[origin]
	if !ok {
		return false
	}
	return rec.MutationAllowed && rec.Classification == ClassSyntheticControlled
}

// CanonicalCleanPath normalizes a URL path and defends against directory traversal.
func CanonicalCleanPath(rawPath string) (string, error) {
	unescaped, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", fmt.Errorf("path unescape error: %w", err)
	}

	// Reject null bytes (raw or unescaped)
	if strings.ContainsRune(unescaped, 0) || strings.Contains(rawPath, "%00") {
		return "", ErrPathTraversalDetected
	}

	// Reject raw or unescaped traversal indicators
	lowerRaw := strings.ToLower(rawPath)
	if strings.Contains(lowerRaw, "%2e%2e") || strings.Contains(lowerRaw, "%5c") || strings.Contains(unescaped, "..") || strings.Contains(unescaped, "\\") {
		return "", ErrPathTraversalDetected
	}

	cleaned := path.Clean("/" + unescaped)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrPathTraversalDetected
	}

	return cleaned, nil
}

// EndpointApprovalKey computes the composite approval identifier.
func EndpointApprovalKey(origin, method, cleanPath string) string {
	return strings.ToLower(origin) + "|" + strings.ToUpper(method) + "|" + cleanPath
}

// LocalScopeValidator enforces destination scope at URL, DNS, socket, and redirect levels.
type LocalScopeValidator struct {
	AllowedOrigins    map[string]struct{}
	ApprovedEndpoints map[string]struct{}
	Registry          *TrustedFixtureRegistry
}

// NewLocalScopeValidator constructs a new local scope validator.
func NewLocalScopeValidator(allowedOrigins []string, registry *TrustedFixtureRegistry) *LocalScopeValidator {
	if registry == nil {
		registry = NewTrustedFixtureRegistry()
	}
	origins := make(map[string]struct{})
	for _, o := range allowedOrigins {
		origins[strings.ToLower(o)] = struct{}{}
	}
	return &LocalScopeValidator{
		AllowedOrigins:    origins,
		ApprovedEndpoints: make(map[string]struct{}),
		Registry:          registry,
	}
}

// ApproveEndpoint registers an exact origin + method + path approval tuple.
func (v *LocalScopeValidator) ApproveEndpoint(origin, method, rawPath string) error {
	clean, err := CanonicalCleanPath(rawPath)
	if err != nil {
		return err
	}
	key := EndpointApprovalKey(origin, method, clean)
	v.ApprovedEndpoints[key] = struct{}{}
	v.AllowedOrigins[strings.ToLower(origin)] = struct{}{}
	return nil
}

// ValidateRequest checks that a request origin and endpoint are approved.
func (v *LocalScopeValidator) ValidateRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("request or URL is nil")
	}

	orig := strings.ToLower(req.URL.Scheme + "://" + req.URL.Host)
	if _, ok := v.AllowedOrigins[orig]; !ok {
		return fmt.Errorf("%w: %s", ErrOriginNotAllowed, orig)
	}

	clean, err := CanonicalCleanPath(req.URL.Path)
	if err != nil {
		return err
	}

	key := EndpointApprovalKey(orig, req.Method, clean)
	if _, ok := v.ApprovedEndpoints[key]; !ok {
		return fmt.Errorf("%w: %s %s on %s", ErrEndpointNotApprovedForOrigin, req.Method, clean, orig)
	}

	// Mutation policy check: if method is state-changing, verify fixture registry
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch || req.Method == http.MethodDelete {
		if !v.Registry.IsMutationAllowed(orig) {
			return ErrMutationsForbiddenOnLiveTarget
		}
	}

	return nil
}

// SafeDialContext performs pre-dial loopback resolution and post-connect socket verification.
func (v *LocalScopeValidator) SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w for host %s: %v", ErrDNSResolutionEmpty, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w for host %s", ErrDNSResolutionEmpty, host)
	}

	for _, ip := range ips {
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: %s resolved to %s", ErrNonLoopbackResolved, host, ip.String())
		}
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	targetAddr := net.JoinHostPort(ips[0].String(), port)
	conn, err := dialer.DialContext(ctx, network, targetAddr)
	if err != nil {
		return nil, err
	}

	// Post-connect socket verification
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !tcpAddr.IP.IsLoopback() {
		_ = conn.Close()
		return nil, ErrSocketDestinationEscaped
	}

	return conn, nil
}

// TargetResource records an object and its identity ownership metadata.
type TargetResource struct {
	ID                string            `json:"id"`
	OwnerPersonaID    string            `json:"owner_persona_id"`
	OwnerRole         PersonaRole       `json:"owner_role"`
	EndpointTemplate  string            `json:"endpoint_template"`
	ParamLocation     string            `json:"param_location"` // "path", "query", or "body"
	ParamName         string            `json:"param_name"`
	OwnerIdentifier   string            `json:"owner_identifier"`
	AltIdentifier     string            `json:"alt_identifier"`
	PrivateAttributes map[string]string `json:"-"` // Redacted from JSON
}

// FunctionEndpoint represents an administrative or privileged functional route.
type FunctionEndpoint struct {
	Path                string      `json:"path"`
	Method              string      `json:"method"`
	AuthorizedRole      PersonaRole `json:"authorized_role"`
	AdminPersonaID      string      `json:"admin_persona_id"`
	PrivilegedIndicator string      `json:"privileged_indicator"`
}

// AuthzFinding models an assessment finding with full provenance.
type AuthzFinding struct {
	ID                         string        `json:"id"`
	TestVectorID               string        `json:"test_vector_id"`
	VulnerabilityCorrelationID string        `json:"vulnerability_correlation_id"`
	Category                   AuthzCategory `json:"category"`
	SecondaryMechanisms        []string      `json:"secondary_mechanisms,omitempty"`
	OWASP                      string        `json:"owasp"`
	CWE                        string        `json:"cwe"`
	Status                     AuthzStatus   `json:"status"`
	Endpoint                   string        `json:"endpoint"`
	Method                     string        `json:"method"`
	Parameter                  string        `json:"parameter,omitempty"`
	OwnerPersonaID             string        `json:"owner_persona_id,omitempty"`
	AssessorPersonaID          string        `json:"assessor_persona_id"`
	AssessorRole               PersonaRole   `json:"assessor_role"`
	BaselineStatus             int           `json:"baseline_status"`
	ProbeStatus                int           `json:"probe_status"`
	EvidenceProof              string        `json:"evidence_proof,omitempty"`
	EvidenceDetails            string        `json:"evidence_details,omitempty"`
	SanitizedPoC               string        `json:"sanitized_poc,omitempty"`
	Timestamp                  time.Time     `json:"timestamp"`
}

// ComputeTestVectorID computes the execution-specific identity.
func ComputeTestVectorID(origin, route, method, paramLoc, paramName, testedVal, ownerID, assessorID, mechanism string) string {
	raw := origin + "|" + route + "|" + method + "|" + paramLoc + "|" + paramName + "|" + testedVal + "|" + ownerID + "|" + assessorID + "|" + mechanism
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ComputeVulnerabilityCorrelationID computes the underlying defect identity.
func ComputeVulnerabilityCorrelationID(origin, normRoute, method, paramLoc, paramName, resourceID, ownerID, boundary string) string {
	raw := origin + "|" + normRoute + "|" + method + "|" + paramLoc + "|" + paramName + "|" + resourceID + "|" + ownerID + "|" + boundary
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateSanitizedPoC formats a safe curl command for reproduction.
func GenerateSanitizedPoC(method, targetURL string, hasAuth bool, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -s -i -X %s %q", method, targetURL))
	if hasAuth {
		sb.WriteString(" -H \"Authorization: Bearer <AUTHENTICATED_TOKEN_REDACTED>\"")
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf(" -d %q", body))
	}
	return sb.String()
}

// AuthzMatrixConfig provides operational tuning and security boundaries.
type AuthzMatrixConfig struct {
	Orchestrator    *MultiPersonaOrchestrator
	ScopeValidator  *LocalScopeValidator
	AllowMutations  bool
	RetryMaxCount   int
	RetryBackoff    time.Duration
}

// AuthzMatrixEngine coordinates authorization evaluations across personas.
type AuthzMatrixEngine struct {
	cfg       AuthzMatrixConfig
	orch      *MultiPersonaOrchestrator
	transport *http.Transport
	client    *http.Client
}

// NewAuthzMatrixEngine constructs a new matrix engine.
func NewAuthzMatrixEngine(cfg AuthzMatrixConfig) (*AuthzMatrixEngine, error) {
	if cfg.Orchestrator == nil {
		return nil, errors.New("multi-persona orchestrator is required")
	}
	if cfg.ScopeValidator == nil {
		cfg.ScopeValidator = NewLocalScopeValidator(nil, nil)
	}
	if cfg.RetryMaxCount <= 0 {
		cfg.RetryMaxCount = 1
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}

	transport := &http.Transport{
		Proxy:       nil, // Programmatically bypass environment proxies
		DialContext: cfg.ScopeValidator.SafeDialContext,
		TLSClientConfig: &tls.Config{
			ServerName: "", // Left empty: dynamic SNI derived from req.URL.Host
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return cfg.ScopeValidator.ValidateRequest(req)
		},
	}

	return &AuthzMatrixEngine{
		cfg:       cfg,
		orch:      cfg.Orchestrator,
		transport: transport,
		client:    client,
	}, nil
}

// doSafeReadRequest executes a read-only request with scope validation and bounded retries.
func (e *AuthzMatrixEngine) doSafeReadRequest(ctx context.Context, persona *Persona, req *http.Request) (*http.Response, []byte, error) {
	if err := e.cfg.ScopeValidator.ValidateRequest(req); err != nil {
		return nil, nil, err
	}

	var lastErr error
	maxAttempts := 1 + e.cfg.RetryMaxCount

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		resp, err := persona.Do(ctx, req)
		if err == nil {
			body, bErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			_ = resp.Body.Close()
			if bErr != nil {
				return nil, nil, fmt.Errorf("failed to read response body: %w", bErr)
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, body, nil
		}

		lastErr = err
		// Retry only if attempts remain and context not canceled
		if attempt < maxAttempts-1 {
			time.Sleep(e.cfg.RetryBackoff)
		}
	}

	return nil, nil, lastErr
}

// EvaluateObjectAuthorization evaluates horizontal object access control (BOLA).
func (e *AuthzMatrixEngine) EvaluateObjectAuthorization(ctx context.Context, res TargetResource, assessorID string) (*AuthzFinding, error) {
	if res.OwnerPersonaID == "" {
		return nil, ErrResourceOwnerRequired
	}
	if assessorID == "" {
		return nil, ErrAssessorRequired
	}

	ownerPersona, ok := e.orch.GetPersona(res.OwnerPersonaID)
	if !ok {
		return nil, fmt.Errorf("owner persona %q not registered", res.OwnerPersonaID)
	}
	assessorPersona, ok := e.orch.GetPersona(assessorID)
	if !ok {
		return nil, fmt.Errorf("assessor persona %q not registered", assessorID)
	}

	targetURL := strings.ReplaceAll(res.EndpointTemplate, "{"+res.ParamName+"}", res.OwnerIdentifier)
	if res.ParamLocation == "query" && !strings.Contains(targetURL, res.ParamName+"=") {
		delim := "?"
		if strings.Contains(targetURL, "?") {
			delim = "&"
		}
		targetURL = fmt.Sprintf("%s%s%s=%s", targetURL, delim, res.ParamName, res.OwnerIdentifier)
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}
	origin := u.Scheme + "://" + u.Host

	// STEP 1: Baseline Request (Resource Owner)
	baselineReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create baseline request: %w", err)
	}

	baseResp, baseBody, err := e.doSafeReadRequest(ctx, ownerPersona, baselineReq)
	if err != nil {
		return &AuthzFinding{
			Category:          CategoryBOLA,
			Status:            StatusInconclusive,
			Endpoint:          targetURL,
			Method:            http.MethodGet,
			OwnerPersonaID:    res.OwnerPersonaID,
			AssessorPersonaID: assessorID,
			EvidenceDetails:   fmt.Sprintf("Owner baseline failed with error: %v", err),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	// Validate baseline contract for GET: requires HTTP 200 + non-empty body
	if baseResp.StatusCode != http.StatusOK || len(bytes.TrimSpace(baseBody)) == 0 {
		return &AuthzFinding{
			Category:          CategoryBOLA,
			Status:            StatusInconclusive,
			Endpoint:          targetURL,
			Method:            http.MethodGet,
			OwnerPersonaID:    res.OwnerPersonaID,
			AssessorPersonaID: assessorID,
			BaselineStatus:    baseResp.StatusCode,
			EvidenceDetails:   fmt.Sprintf("Owner baseline returned non-200 or empty payload: status %d", baseResp.StatusCode),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	// STEP 2: Cross-Persona Probe (Assessor Identity)
	probeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create probe request: %w", err)
	}

	probeResp, probeBody, err := e.doSafeReadRequest(ctx, assessorPersona, probeReq)
	if err != nil {
		return &AuthzFinding{
			Category:          CategoryBOLA,
			Status:            StatusInconclusive,
			Endpoint:          targetURL,
			Method:            http.MethodGet,
			OwnerPersonaID:    res.OwnerPersonaID,
			AssessorPersonaID: assessorID,
			BaselineStatus:    baseResp.StatusCode,
			EvidenceDetails:   fmt.Sprintf("Probe network request failed: %v", err),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	testVecID := ComputeTestVectorID(origin, res.EndpointTemplate, http.MethodGet, res.ParamLocation, res.ParamName, res.OwnerIdentifier, res.OwnerPersonaID, assessorID, "BOLA_CROSS_USER")
	vulnCorrID := ComputeVulnerabilityCorrelationID(origin, res.EndpointTemplate, http.MethodGet, res.ParamLocation, res.ParamName, res.ID, res.OwnerPersonaID, "HORIZONTAL_OBJECT_ACCESS")

	finding := &AuthzFinding{
		ID:                         fmt.Sprintf("finding-%d", time.Now().UnixNano()),
		TestVectorID:               testVecID,
		VulnerabilityCorrelationID: vulnCorrID,
		Category:                   CategoryBOLA,
		OWASP:                      "API1:2023",
		CWE:                        "CWE-639",
		Endpoint:                   targetURL,
		Method:                     http.MethodGet,
		Parameter:                  res.ParamName,
		OwnerPersonaID:             res.OwnerPersonaID,
		AssessorPersonaID:          assessorID,
		AssessorRole:               assessorPersona.Role(),
		BaselineStatus:             baseResp.StatusCode,
		ProbeStatus:                probeResp.StatusCode,
		Timestamp:                  time.Now().UTC(),
	}

	// Evaluation Logic
	if probeResp.StatusCode == http.StatusForbidden || probeResp.StatusCode == http.StatusUnauthorized {
		finding.Status = StatusDefended
		finding.EvidenceDetails = fmt.Sprintf("Access barrier confirmed: server returned HTTP %d to unauthorized assessor", probeResp.StatusCode)
		return finding, nil
	}

	if probeResp.StatusCode == http.StatusOK {
		// Filter false positives: login redirects, soft 401s, trivial empty bodies
		if isLogin, _ := isLoginRedirectOrLoginForm(targetURL, probeResp, probeBody); isLogin {
			finding.Status = StatusDefended
			finding.EvidenceDetails = "Probe redirected to or returned login form (not an authorization leak)"
			return finding, nil
		}
		if isAuthErrorPayload(probeBody) {
			finding.Status = StatusDefended
			finding.EvidenceDetails = "Probe returned HTTP 200 with authentication error payload"
			return finding, nil
		}
		if isEmptyOrTrivialPayload(probeBody) {
			finding.Status = StatusInconclusive
			finding.EvidenceDetails = "Probe returned empty or trivial JSON payload"
			return finding, nil
		}

		// Positive semantic verification: does probe body contain owner's private attributes?
		matchesCount := 0
		bodyStr := string(probeBody)
		for attrKey, attrVal := range res.PrivateAttributes {
			if attrVal != "" && strings.Contains(bodyStr, attrVal) {
				// Prevent reflection false positive: attribute must not be the tested parameter value itself
				if attrVal != res.OwnerIdentifier {
					matchesCount++
				}
			}
			_ = attrKey
		}

		if matchesCount > 0 {
			finding.Status = StatusVerifiedDefect
			finding.EvidenceProof = fmt.Sprintf("Unauthorized assessor %s received owner's private attributes in response (%d verified attributes matched)", assessorID, matchesCount)
			finding.SanitizedPoC = GenerateSanitizedPoC(http.MethodGet, targetURL, assessorPersona.HasBearerToken(), "")
			return finding, nil
		}

		finding.Status = StatusInconclusive
		finding.EvidenceDetails = "Probe returned HTTP 200 but did not match verified owner private attributes"
		return finding, nil
	}

	finding.Status = StatusInconclusive
	finding.EvidenceDetails = fmt.Sprintf("Unexpected status code %d", probeResp.StatusCode)
	return finding, nil
}

// EvaluateDirectReference evaluates Insecure Direct Object Reference (IDOR) via parameter substitution.
func (e *AuthzMatrixEngine) EvaluateDirectReference(ctx context.Context, res TargetResource, assessorID string) (*AuthzFinding, error) {
	if res.AltIdentifier == "" {
		return nil, errors.New("alternate identifier required for direct reference substitution test")
	}

	assessorPersona, ok := e.orch.GetPersona(assessorID)
	if !ok {
		return nil, fmt.Errorf("assessor persona %q not registered", assessorID)
	}

	// Construct URL targeting alternate identifier
	targetURL := strings.ReplaceAll(res.EndpointTemplate, "{"+res.ParamName+"}", res.AltIdentifier)
	if res.ParamLocation == "query" && !strings.Contains(targetURL, res.ParamName+"=") {
		delim := "?"
		if strings.Contains(targetURL, "?") {
			delim = "&"
		}
		targetURL = fmt.Sprintf("%s%s%s=%s", targetURL, delim, res.ParamName, res.AltIdentifier)
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", targetURL, err)
	}
	origin := u.Scheme + "://" + u.Host

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, body, err := e.doSafeReadRequest(ctx, assessorPersona, req)
	if err != nil {
		return &AuthzFinding{
			Category:          CategoryIDOR,
			Status:            StatusInconclusive,
			Endpoint:          targetURL,
			Method:            http.MethodGet,
			AssessorPersonaID: assessorID,
			EvidenceDetails:   fmt.Sprintf("IDOR request failed: %v", err),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	testVecID := ComputeTestVectorID(origin, res.EndpointTemplate, http.MethodGet, res.ParamLocation, res.ParamName, res.AltIdentifier, res.OwnerPersonaID, assessorID, "IDOR_PARAM_SUBSTITUTION")
	vulnCorrID := ComputeVulnerabilityCorrelationID(origin, res.EndpointTemplate, http.MethodGet, res.ParamLocation, res.ParamName, res.ID, res.OwnerPersonaID, "HORIZONTAL_OBJECT_ACCESS")

	finding := &AuthzFinding{
		ID:                         fmt.Sprintf("finding-%d", time.Now().UnixNano()),
		TestVectorID:               testVecID,
		VulnerabilityCorrelationID: vulnCorrID,
		Category:                   CategoryIDOR,
		OWASP:                      "API1:2023",
		CWE:                        "CWE-639",
		Endpoint:                   targetURL,
		Method:                     http.MethodGet,
		Parameter:                  res.ParamName,
		OwnerPersonaID:             res.OwnerPersonaID,
		AssessorPersonaID:          assessorID,
		AssessorRole:               assessorPersona.Role(),
		ProbeStatus:                resp.StatusCode,
		Timestamp:                  time.Now().UTC(),
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		finding.Status = StatusDefended
		finding.EvidenceDetails = fmt.Sprintf("Direct reference substitution defended: server returned status %d", resp.StatusCode)
		return finding, nil
	}

	if resp.StatusCode == http.StatusOK {
		if isLogin, _ := isLoginRedirectOrLoginForm(targetURL, resp, body); isLogin || isAuthErrorPayload(body) || isEmptyOrTrivialPayload(body) {
			finding.Status = StatusDefended
			return finding, nil
		}

		finding.Status = StatusVerifiedDefect
		finding.EvidenceProof = fmt.Sprintf("Direct object reference %s=%s accessible to persona %s (status 200)", res.ParamName, res.AltIdentifier, assessorID)
		finding.SanitizedPoC = GenerateSanitizedPoC(http.MethodGet, targetURL, assessorPersona.HasBearerToken(), "")
		return finding, nil
	}

	finding.Status = StatusInconclusive
	return finding, nil
}

// EvaluateFunctionAuthorization evaluates Broken Function Level Authorization (BFLA).
// Protocol Rule: Standard user denial is NEVER a defended barrier if the admin baseline also fails.
func (e *AuthzMatrixEngine) EvaluateFunctionAuthorization(ctx context.Context, fn FunctionEndpoint, assessorID string) (*AuthzFinding, error) {
	if fn.AdminPersonaID == "" {
		return nil, errors.New("admin persona ID is required for BFLA baseline")
	}

	adminPersona, ok := e.orch.GetPersona(fn.AdminPersonaID)
	if !ok {
		return nil, fmt.Errorf("admin persona %q not registered", fn.AdminPersonaID)
	}
	assessorPersona, ok := e.orch.GetPersona(assessorID)
	if !ok {
		return nil, fmt.Errorf("assessor persona %q not registered", assessorID)
	}

	u, err := url.Parse(fn.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid function URL %q: %w", fn.Path, err)
	}
	origin := u.Scheme + "://" + u.Host

	// PHASE 1: Administrative Baseline Execution
	adminReq, err := http.NewRequestWithContext(ctx, fn.Method, fn.Path, nil)
	if err != nil {
		return nil, err
	}

	adminResp, adminBody, err := e.doSafeReadRequest(ctx, adminPersona, adminReq)
	if err != nil {
		return &AuthzFinding{
			Category:          CategoryBFLA,
			Status:            StatusInconclusive,
			Endpoint:          fn.Path,
			Method:            fn.Method,
			AssessorPersonaID: assessorID,
			EvidenceDetails:   fmt.Sprintf("%v: %v", ErrAdminBaselineFailed, err),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	// Admin baseline contract: requires HTTP 200/201 and presence of PrivilegedIndicator
	if adminResp.StatusCode != http.StatusOK && adminResp.StatusCode != http.StatusCreated {
		return &AuthzFinding{
			Category:          CategoryBFLA,
			Status:            StatusInconclusive,
			Endpoint:          fn.Path,
			Method:            fn.Method,
			AssessorPersonaID: assessorID,
			BaselineStatus:    adminResp.StatusCode,
			EvidenceDetails:   fmt.Sprintf("Administrative baseline failed with status %d (endpoint broken or unauthorized)", adminResp.StatusCode),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	if fn.PrivilegedIndicator != "" && !strings.Contains(string(adminBody), fn.PrivilegedIndicator) {
		return &AuthzFinding{
			Category:          CategoryBFLA,
			Status:            StatusInconclusive,
			Endpoint:          fn.Path,
			Method:            fn.Method,
			AssessorPersonaID: assessorID,
			BaselineStatus:    adminResp.StatusCode,
			EvidenceDetails:   "Administrative baseline did not return expected privileged indicator structure",
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	// PHASE 2: Assessor Probe (Standard User or Anonymous)
	probeReq, err := http.NewRequestWithContext(ctx, fn.Method, fn.Path, nil)
	if err != nil {
		return nil, err
	}

	probeResp, probeBody, err := e.doSafeReadRequest(ctx, assessorPersona, probeReq)
	if err != nil {
		return &AuthzFinding{
			Category:          CategoryBFLA,
			Status:            StatusInconclusive,
			Endpoint:          fn.Path,
			Method:            fn.Method,
			AssessorPersonaID: assessorID,
			BaselineStatus:    adminResp.StatusCode,
			EvidenceDetails:   fmt.Sprintf("Probe request failed: %v", err),
			Timestamp:         time.Now().UTC(),
		}, nil
	}

	testVecID := ComputeTestVectorID(origin, fn.Path, fn.Method, "path", "", "", fn.AdminPersonaID, assessorID, "BFLA_FUNCTION_PROBE")
	vulnCorrID := ComputeVulnerabilityCorrelationID(origin, fn.Path, fn.Method, "path", "", fn.Path, fn.AdminPersonaID, "VERTICAL_FUNCTION_ACCESS")

	finding := &AuthzFinding{
		ID:                         fmt.Sprintf("finding-%d", time.Now().UnixNano()),
		TestVectorID:               testVecID,
		VulnerabilityCorrelationID: vulnCorrID,
		Category:                   CategoryBFLA,
		OWASP:                      "API5:2023",
		CWE:                        "CWE-285",
		Endpoint:                   fn.Path,
		Method:                     fn.Method,
		OwnerPersonaID:             fn.AdminPersonaID,
		AssessorPersonaID:          assessorID,
		AssessorRole:               assessorPersona.Role(),
		BaselineStatus:             adminResp.StatusCode,
		ProbeStatus:                probeResp.StatusCode,
		Timestamp:                  time.Now().UTC(),
	}

	if probeResp.StatusCode == http.StatusForbidden || probeResp.StatusCode == http.StatusUnauthorized {
		finding.Status = StatusDefended
		finding.EvidenceDetails = fmt.Sprintf("Function access defended: server returned status %d to unprivileged role %s", probeResp.StatusCode, assessorPersona.Role())
		return finding, nil
	}

	if probeResp.StatusCode == http.StatusOK {
		if isLogin, _ := isLoginRedirectOrLoginForm(fn.Path, probeResp, probeBody); isLogin || isAuthErrorPayload(probeBody) || isEmptyOrTrivialPayload(probeBody) {
			finding.Status = StatusDefended
			return finding, nil
		}

		if fn.PrivilegedIndicator != "" && strings.Contains(string(probeBody), fn.PrivilegedIndicator) {
			finding.Status = StatusVerifiedDefect
			finding.EvidenceProof = fmt.Sprintf("Unprivileged assessor %s executed privileged function %s and received verified administrative data", assessorID, fn.Path)
			finding.SanitizedPoC = GenerateSanitizedPoC(fn.Method, fn.Path, assessorPersona.HasBearerToken(), "")
			return finding, nil
		}

		finding.Status = StatusInconclusive
		finding.EvidenceDetails = "Probe returned HTTP 200 but did not match administrative execution proof"
		return finding, nil
	}

	finding.Status = StatusInconclusive
	return finding, nil
}

// EvaluateThreeStepMutation performs safe three-step mutation verification on synthetic fixtures.
func (e *AuthzMatrixEngine) EvaluateThreeStepMutation(ctx context.Context, getURL, putURL string, ownerPersona, assessorPersona *Persona, mutatingBody string, expectedVal string) (AuthzStatus, error) {
	u, err := url.Parse(putURL)
	if err != nil {
		return StatusInconclusive, err
	}
	origin := u.Scheme + "://" + u.Host

	// Pre-condition: Target MUST be an engine-registered synthetic fixture
	if !e.cfg.ScopeValidator.Registry.IsMutationAllowed(origin) {
		return StatusInconclusive, ErrMutationsForbiddenOnLiveTarget
	}

	// 1. Pre-state read (Owner)
	preReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	preResp, preBody, err := e.doSafeReadRequest(ctx, ownerPersona, preReq)
	if err != nil || preResp.StatusCode != http.StatusOK {
		return StatusInconclusive, fmt.Errorf("pre-state read failed: %v", err)
	}
	preVal := string(preBody)

	// 2. Mutating probe (Assessor)
	mutReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, putURL, strings.NewReader(mutatingBody))
	mutReq.Header.Set("Content-Type", "application/json")
	if err := e.cfg.ScopeValidator.ValidateRequest(mutReq); err != nil {
		return StatusInconclusive, err
	}

	probeResp, probeErr := assessorPersona.Do(ctx, mutReq)
	if probeErr != nil {
		return StatusInconclusive, probeErr
	}
	defer probeResp.Body.Close()

	// 3. Post-state read (Owner's independent client)
	postReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	postResp, postBody, err := e.doSafeReadRequest(ctx, ownerPersona, postReq)
	if err != nil || postResp.StatusCode != http.StatusOK {
		return StatusInconclusive, fmt.Errorf("post-state read failed: %v", err)
	}
	postVal := string(postBody)

	// Outcome Classification Contract
	if probeResp.StatusCode == http.StatusForbidden || probeResp.StatusCode == http.StatusUnauthorized {
		if postVal == preVal {
			return StatusDefended, nil
		}
		return StatusInconclusive, nil
	}

	if strings.Contains(postVal, expectedVal) && !strings.Contains(preVal, expectedVal) {
		return StatusVerifiedDefect, nil
	}

	return StatusInconclusive, nil
}
