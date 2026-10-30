package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Common multi-persona errors.
var (
	ErrPersonaNotFound       = errors.New("persona not found")
	ErrPersonaAlreadyExists  = errors.New("persona ID already exists")
	ErrInvalidPersonaConfig  = errors.New("invalid persona configuration")
	ErrPersonaAuthFailed     = errors.New("persona authentication failed")
	ErrOrchestratorClosed    = errors.New("orchestrator is closed")
)

// PersonaRole defines the standard authorization roles required by Roadmap Step 3.4.
type PersonaRole string

const (
	RoleVictim    PersonaRole = "VICTIM"     // Persona A: Primary Authenticated User (Target)
	RoleAttacker  PersonaRole = "ATTACKER"   // Persona B: Secondary Authenticated User (Peer Tenant)
	RoleAnonymous PersonaRole = "ANONYMOUS"  // Persona C: Unauthenticated / Anonymous Guest
	RoleAdmin     PersonaRole = "ADMIN"      // Persona D: Administrative Privileged User
	RoleCustom    PersonaRole = "CUSTOM"     // Extensible custom persona
)

// AuthMethod identifies how the persona authenticates against the target application.
type AuthMethod string

const (
	AuthMethodNone        AuthMethod = "NONE"          // Anonymous / unauthenticated guest
	AuthMethodBearer      AuthMethod = "BEARER"        // Static or dynamic JWT / Bearer token
	AuthMethodCookieMacro AuthMethod = "COOKIE_MACRO"  // Phase 3.1 LoginMacro-driven cookie session
	AuthMethodHeader      AuthMethod = "CUSTOM_HEADER" // Custom auth header (e.g. API key)
)

// BearerLoginConfig defines an automated REST/JSON login request to obtain a Bearer token.
type BearerLoginConfig struct {
	URL         string            `json:"url"`
	UsernameKey string            `json:"username_key,omitempty"` // default "username"
	PasswordKey string            `json:"password_key,omitempty"` // default "password"
	TokenKey    string            `json:"token_key,omitempty"`    // default searches "auth_token", "access_token", "token", "jwt"
	ExtraFields map[string]string `json:"extra_fields,omitempty"`
}

// PersonaConfig defines the declarative setup for an individual identity.
// Security: Passwords, tokens, custom secret headers, and credentials are tagged json:"-"
// to prevent accidental serialization into JSON, logs, test output, or evidence receipts.
type PersonaConfig struct {
	ID                string                `json:"id"`
	Role              PersonaRole           `json:"role"`
	Description       string                `json:"description,omitempty"`
	AuthMethod        AuthMethod            `json:"auth_method"`
	Username          string                `json:"username,omitempty"`
	Email             string                `json:"email,omitempty"`
	Password          string                `json:"-"` // Secret: NEVER serialized
	BearerToken       string                `json:"-"` // Secret: NEVER serialized
	CustomHeaders     map[string]string     `json:"-"` // Secret: NEVER serialized
	BearerLogin       *BearerLoginConfig    `json:"-"` // Secret credentials inside: NEVER serialized
	LoginMacroConfig  *LoginMacroConfig     `json:"-"` // Secret credentials inside: NEVER serialized
	SessionMonitorCfg *SessionMonitorConfig `json:"-"` // Secret credentials inside: NEVER serialized
	CSRFSync          *CSRFSynchronizer     `json:"-"` // Isolated or shared CSRF engine
}

// PersonaSummary provides safe, non-sensitive metadata for logging and reporting.
type PersonaSummary struct {
	ID          string      `json:"id"`
	Role        PersonaRole `json:"role"`
	Description string      `json:"description,omitempty"`
	AuthMethod  AuthMethod  `json:"auth_method"`
	Username    string      `json:"username,omitempty"`
	Email       string      `json:"email,omitempty"`
	HasBearer   bool        `json:"has_bearer"`
	HasSession  bool        `json:"has_session"`
	HasMonitor  bool        `json:"has_monitor"`
	HasCSRF     bool        `json:"has_csrf"`
}

// Persona represents an active, isolated identity context.
// In accordance with security requirements:
// 1. Raw cookie jars and bearer tokens are not exposed via public getters.
// 2. The anonymous persona receives its own independent cookie jar and client.
// 3. All operations clone requests defensively before modifying headers or cookies.
type Persona struct {
	id            string
	role          PersonaRole
	description   string
	authMethod    AuthMethod
	username      string
	email         string
	mu            sync.RWMutex
	jar           http.CookieJar        // Independent cookie jar
	client        *http.Client          // Isolated HTTP client bound to jar
	bearerToken   string                // Protected bearer token
	customHeaders map[string]string     // Isolated headers
	session       *MacroSession         // Active macro session, if applicable
	macro         *LoginMacro           // If using macro
	monitor       *SessionMonitor       // Optional keep-alive monitor
	csrfSync      *CSRFSynchronizer     // Associated CSRF synchronizer
	bearerLogin   *BearerLoginConfig    // Bearer login configuration
	password      string                // Stored strictly in-memory
}

// NewPersona creates an isolated persona instance from configuration.
func NewPersona(cfg PersonaConfig, transport http.RoundTripper) (*Persona, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("%w: ID cannot be empty", ErrInvalidPersonaConfig)
	}
	if cfg.Role == "" {
		cfg.Role = RoleCustom
	}
	if cfg.AuthMethod == "" {
		if cfg.Role == RoleAnonymous {
			cfg.AuthMethod = AuthMethodNone
		} else if cfg.BearerToken != "" || cfg.BearerLogin != nil {
			cfg.AuthMethod = AuthMethodBearer
		} else if cfg.LoginMacroConfig != nil {
			cfg.AuthMethod = AuthMethodCookieMacro
		} else if len(cfg.CustomHeaders) > 0 {
			cfg.AuthMethod = AuthMethodHeader
		} else {
			cfg.AuthMethod = AuthMethodNone
		}
	}

	// Mandatory Security Requirement: Every persona (including Anonymous) receives
	// its own independent cookie jar and isolated HTTP client.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create isolated cookie jar: %w", err)
	}

	client := &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Clone custom headers map
	headersCopy := make(map[string]string)
	for k, v := range cfg.CustomHeaders {
		headersCopy[k] = v
	}

	p := &Persona{
		id:            cfg.ID,
		role:          cfg.Role,
		description:   cfg.Description,
		authMethod:    cfg.AuthMethod,
		username:      cfg.Username,
		email:         cfg.Email,
		password:      cfg.Password,
		jar:           jar,
		client:        client,
		bearerToken:   cfg.BearerToken,
		customHeaders: headersCopy,
		csrfSync:      cfg.CSRFSync,
		bearerLogin:   cfg.BearerLogin,
	}

	if cfg.LoginMacroConfig != nil {
		p.macro = NewLoginMacro(*cfg.LoginMacroConfig)
	}

	if cfg.SessionMonitorCfg != nil {
		p.monitor = NewSessionMonitor(*cfg.SessionMonitorCfg)
	}

	return p, nil
}

// ID returns the unique identifier for this persona.
func (p *Persona) ID() string {
	return p.id
}

// Role returns the role assigned to this persona.
func (p *Persona) Role() PersonaRole {
	return p.role
}

// AuthMethod returns the authentication method configured for this persona.
func (p *Persona) AuthMethod() AuthMethod {
	return p.authMethod
}

// Username returns the username associated with this persona.
func (p *Persona) Username() string {
	return p.username
}

// Email returns the email associated with this persona.
func (p *Persona) Email() string {
	return p.email
}

// Summary returns a safe, non-sensitive summary of this persona for logging/evidence.
func (p *Persona) Summary() PersonaSummary {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return PersonaSummary{
		ID:          p.id,
		Role:        p.role,
		Description: p.description,
		AuthMethod:  p.authMethod,
		Username:    p.username,
		Email:       p.email,
		HasBearer:   p.bearerToken != "",
		HasSession:  p.session != nil && p.session.Authenticated,
		HasMonitor:  p.monitor != nil,
		HasCSRF:     p.csrfSync != nil,
	}
}

// HasBearerToken reports whether a bearer token is present without exposing its value.
func (p *Persona) HasBearerToken() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.bearerToken != ""
}

// BearerTokenHash returns the SHA-256 fingerprint of the bearer token.
// Allows tests to cryptographically verify token distinctness and isolation
// without exposing the cleartext secret.
func (p *Persona) BearerTokenHash() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.bearerToken == "" {
		return ""
	}
	h := sha256.Sum256([]byte(p.bearerToken))
	return hex.EncodeToString(h[:])
}

// SetBearerToken safely updates the bearer token in memory.
func (p *Persona) SetBearerToken(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bearerToken = token
	if p.authMethod == AuthMethodNone && token != "" {
		p.authMethod = AuthMethodBearer
	}
}

// SetCustomHeader sets a custom header on the persona.
func (p *Persona) SetCustomHeader(key, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.customHeaders[key] = value
}

// CapturedCookieNames returns the names of cookies present in this persona's jar for a URL.
// Raw cookie values are intentionally not returned to avoid credential leakage.
func (p *Persona) CapturedCookieNames(targetURL *url.URL) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.jar == nil || targetURL == nil {
		return nil
	}
	cookies := p.jar.Cookies(targetURL)
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return names
}

// SetCookie adds a cookie directly to this persona's isolated cookie jar.
func (p *Persona) SetCookie(targetURL *url.URL, cookie *http.Cookie) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jar != nil && targetURL != nil && cookie != nil {
		p.jar.SetCookies(targetURL, []*http.Cookie{cookie})
	}
}

// SetCSRFSynchronizer binds a CSRF synchronizer to this persona.
func (p *Persona) SetCSRFSynchronizer(csrf *CSRFSynchronizer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.csrfSync = csrf
}

// SetSessionMonitor binds a session monitor to this persona.
func (p *Persona) SetSessionMonitor(monitor *SessionMonitor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.monitor = monitor
}

// Authenticate executes the authentication procedure for this persona.
func (p *Persona) Authenticate(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.authMethod {
	case AuthMethodNone:
		// Anonymous requires no authentication
		return nil

	case AuthMethodBearer:
		// If bearer token is already set, we're ready
		if p.bearerToken != "" {
			return nil
		}
		// If BearerLogin is configured, execute REST/JSON login
		if p.bearerLogin != nil {
			token, err := p.executeBearerLoginLocked(ctx)
			if err != nil {
				return fmt.Errorf("%w: bearer login failed for persona %s: %v", ErrPersonaAuthFailed, p.id, err)
			}
			p.bearerToken = token
			return nil
		}
		// If LoginMacro is configured, execute it and extract token or cookies
		if p.macro != nil {
			sess, err := p.macro.Execute(ctx)
			if err != nil {
				return fmt.Errorf("%w: macro execution failed for persona %s: %v", ErrPersonaAuthFailed, p.id, err)
			}
			p.session = sess
			if sess.BearerToken != "" {
				p.bearerToken = sess.BearerToken
			}
			return nil
		}
		return fmt.Errorf("%w: persona %s configured for bearer auth but no token or login method provided", ErrInvalidPersonaConfig, p.id)

	case AuthMethodCookieMacro:
		if p.monitor != nil {
			sess, err := p.monitor.GetSession(ctx)
			if err != nil {
				return fmt.Errorf("%w: monitor session failed for persona %s: %v", ErrPersonaAuthFailed, p.id, err)
			}
			p.session = sess
			return nil
		}
		if p.macro != nil {
			sess, err := p.macro.Execute(ctx)
			if err != nil {
				return fmt.Errorf("%w: macro failed for persona %s: %v", ErrPersonaAuthFailed, p.id, err)
			}
			p.session = sess
			return nil
		}
		return fmt.Errorf("%w: persona %s configured for cookie macro but no macro or monitor provided", ErrInvalidPersonaConfig, p.id)

	case AuthMethodHeader:
		// Header auth is ready if custom headers are defined
		return nil

	default:
		return nil
	}
}

// executeBearerLoginLocked dispatches a JSON login request to retrieve an authentication token.
func (p *Persona) executeBearerLoginLocked(ctx context.Context) (string, error) {
	bl := p.bearerLogin
	if bl == nil || bl.URL == "" {
		return "", errors.New("missing bearer login URL")
	}

	uKey := bl.UsernameKey
	if uKey == "" {
		uKey = "username"
	}
	pKey := bl.PasswordKey
	if pKey == "" {
		pKey = "password"
	}

	payload := map[string]any{
		uKey: p.username,
		pKey: p.password,
	}
	for k, v := range bl.ExtraFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bl.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("login returned HTTP %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read login response: %w", err)
	}

	var respMap map[string]any
	if err := json.Unmarshal(respBytes, &respMap); err != nil {
		return "", fmt.Errorf("failed to parse login response JSON: %w", err)
	}

	// Extract token: check configured key, then common token keys
	tokenKeys := []string{"auth_token", "access_token", "token", "jwt", "id_token"}
	if bl.TokenKey != "" {
		tokenKeys = append([]string{bl.TokenKey}, tokenKeys...)
	}

	for _, k := range tokenKeys {
		if val, ok := respMap[k].(string); ok && val != "" {
			return val, nil
		}
	}

	// Check nested authentication.token (e.g. Juice Shop format)
	if authObj, ok := respMap["authentication"].(map[string]any); ok {
		for _, k := range tokenKeys {
			if val, ok := authObj[k].(string); ok && val != "" {
				return val, nil
			}
		}
	}

	// Check nested data.token
	if dataObj, ok := respMap["data"].(map[string]any); ok {
		for _, k := range tokenKeys {
			if val, ok := dataObj[k].(string); ok && val != "" {
				return val, nil
			}
		}
	}

	return "", fmt.Errorf("no authentication token found in login response keys: %v", tokenKeys)
}

// injectAuthInternal injects the persona's credentials into a request clone.
// The caller must provide an already-cloned request.
func (p *Persona) injectAuthInternal(req *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.role {
	case RoleAnonymous:
		// Requirement 2.3: Anonymous persona has its own empty cookie jar and isolated client.
		// Stripping incoming headers guarantees no outer/caller auth leaks through.
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
		for k, v := range p.customHeaders {
			req.Header.Set(k, v)
		}

	default:
		if p.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+p.bearerToken)
		}
		for k, v := range p.customHeaders {
			req.Header.Set(k, v)
		}
	}
}

// Do executes an HTTP request under this persona's identity.
// Requirement 2.5: The request is cloned defensively before any header or authentication mutation.
// Requirement 2.6: Concurrent requests using the same original request pointer will not collide.
func (p *Persona) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	// Deep clone request including headers
	cloned := req.Clone(ctx)
	p.injectAuthInternal(cloned)

	p.mu.RLock()
	mon := p.monitor
	cli := p.client
	csrf := p.csrfSync
	p.mu.RUnlock()

	var resp *http.Response
	var err error
	if mon != nil {
		resp, err = mon.Do(cloned)
	} else {
		resp, err = cli.Do(cloned)
	}

	if err != nil {
		return nil, err
	}

	// Auto-extract dynamic anti-CSRF token if configured
	if csrf != nil && csrf.cfg.AutoExtract {
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		seqID := csrf.NextSequence(p.id)
		_, _ = csrf.ExtractToken(resp, bodyBytes, p.id, seqID)
	}

	return resp, nil
}

// ExecuteMutating executes a state-changing request under this persona's identity
// with dynamic anti-CSRF synchronization if a synchronizer is attached.
// Requirement 2.7: CSRF state is isolated per persona using p.id as the sessionID.
func (p *Persona) ExecuteMutating(ctx context.Context, req *http.Request) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	cloned := req.Clone(ctx)
	p.injectAuthInternal(cloned)

	p.mu.RLock()
	csrf := p.csrfSync
	mon := p.monitor
	cli := p.client
	p.mu.RUnlock()

	if csrf != nil {
		// Use p.id as sessionID to ensure isolated CSRF token rotation and state per persona
		return csrf.ExecuteMutating(ctx, cli, cloned, p.id)
	}

	if mon != nil {
		return mon.Do(cloned)
	}
	return cli.Do(cloned)
}

// Close terminates any active background resources (e.g. SessionMonitor).
func (p *Persona) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.monitor != nil {
		p.monitor.Close()
		p.monitor = nil
	}
}

// MultiPersonaOrchestrator manages multiple persona contexts simultaneously.
// Requirement 2.4: Supports multiple personas sharing the same role (keyed by persona ID).
// Requirement 2.8: Does not hold global orchestrator locks while performing network I/O.
type MultiPersonaOrchestrator struct {
	mu        sync.RWMutex
	personas  map[string]*Persona
	byRole    map[PersonaRole][]*Persona
	csrfSync  *CSRFSynchronizer
	transport http.RoundTripper
	closed    bool
}

// NewMultiPersonaOrchestrator constructs a new orchestrator.
func NewMultiPersonaOrchestrator(csrfSync *CSRFSynchronizer, transport http.RoundTripper) *MultiPersonaOrchestrator {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &MultiPersonaOrchestrator{
		personas:  make(map[string]*Persona),
		byRole:    make(map[PersonaRole][]*Persona),
		csrfSync:  csrfSync,
		transport: transport,
	}
}

// RegisterPersona adds a new persona to the orchestrator.
func (o *MultiPersonaOrchestrator) RegisterPersona(cfg PersonaConfig) (*Persona, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil, ErrOrchestratorClosed
	}
	if cfg.ID == "" {
		return nil, fmt.Errorf("%w: ID cannot be empty", ErrInvalidPersonaConfig)
	}
	if _, exists := o.personas[cfg.ID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrPersonaAlreadyExists, cfg.ID)
	}

	// If no persona-specific CSRF synchronizer is set, inherit the orchestrator's CSRF synchronizer
	if cfg.CSRFSync == nil && o.csrfSync != nil {
		cfg.CSRFSync = o.csrfSync
	}

	p, err := NewPersona(cfg, o.transport)
	if err != nil {
		return nil, err
	}

	o.personas[p.id] = p
	o.byRole[p.role] = append(o.byRole[p.role], p)
	return p, nil
}

// GetPersona retrieves a persona by its unique ID (primary lookup).
// Requirement 2.8: Lock is acquired and released immediately. No network I/O held under lock.
func (o *MultiPersonaOrchestrator) GetPersona(id string) (*Persona, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	p, ok := o.personas[id]
	return p, ok
}

// GetPersonasByRole retrieves all personas sharing a specific role.
// Requirement 2.4: Supports multiple personas with the same role.
func (o *MultiPersonaOrchestrator) GetPersonasByRole(role PersonaRole) []*Persona {
	o.mu.RLock()
	defer o.mu.RUnlock()
	list := o.byRole[role]
	res := make([]*Persona, len(list))
	copy(res, list)
	return res
}

// GetPrimaryPersonaByRole retrieves the first persona registered for a given role.
func (o *MultiPersonaOrchestrator) GetPrimaryPersonaByRole(role PersonaRole) (*Persona, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	list := o.byRole[role]
	if len(list) == 0 {
		return nil, false
	}
	return list[0], true
}

// ListPersonas returns non-sensitive metadata for all registered personas.
func (o *MultiPersonaOrchestrator) ListPersonas() []PersonaSummary {
	o.mu.RLock()
	defer o.mu.RUnlock()
	summaries := make([]PersonaSummary, 0, len(o.personas))
	for _, p := range o.personas {
		summaries = append(summaries, p.Summary())
	}
	return summaries
}

// AuthenticateAll authenticates all registered personas concurrently.
func (o *MultiPersonaOrchestrator) AuthenticateAll(ctx context.Context) error {
	o.mu.RLock()
	personas := make([]*Persona, 0, len(o.personas))
	for _, p := range o.personas {
		personas = append(personas, p)
	}
	o.mu.RUnlock()

	var wg sync.WaitGroup
	errCh := make(chan error, len(personas))

	for _, p := range personas {
		wg.Add(1)
		go func(target *Persona) {
			defer wg.Done()
			if err := target.Authenticate(ctx); err != nil {
				errCh <- fmt.Errorf("persona %s (%s): %w", target.id, target.role, err)
			}
		}(p)
	}

	wg.Wait()
	close(errCh)

	var errList []string
	for err := range errCh {
		errList = append(errList, err.Error())
	}

	if len(errList) > 0 {
		return fmt.Errorf("%w: %s", ErrPersonaAuthFailed, strings.Join(errList, "; "))
	}
	return nil
}

// ExecuteAs dispatches a request under the identity of the specified persona.
// Requirement 2.8: Orchestrator lock is released immediately after persona resolution,
// ensuring no global lock is held during network I/O.
func (o *MultiPersonaOrchestrator) ExecuteAs(ctx context.Context, personaID string, req *http.Request) (*http.Response, error) {
	p, ok := o.GetPersona(personaID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPersonaNotFound, personaID)
	}
	return p.Do(ctx, req)
}

// ExecuteMutatingAs dispatches a state-changing request under the identity of the specified persona,
// applying isolated anti-CSRF synchronization.
func (o *MultiPersonaOrchestrator) ExecuteMutatingAs(ctx context.Context, personaID string, req *http.Request) (*http.Response, error) {
	p, ok := o.GetPersona(personaID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPersonaNotFound, personaID)
	}
	return p.ExecuteMutating(ctx, req)
}

// Close terminates all managed personas and releases background resources.
func (o *MultiPersonaOrchestrator) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return
	}
	o.closed = true
	for _, p := range o.personas {
		p.Close()
	}
}
