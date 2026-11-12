package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// IdentityContext identifies an active authorization context.
type IdentityContext string

const (
	IdentityUnauthenticated IdentityContext = "UNAUTHENTICATED"
	IdentityUserA           IdentityContext = "USER_A"
	IdentityUserB           IdentityContext = "USER_B"
	IdentityAdmin           IdentityContext = "ADMIN"
)

type identityContextKey struct{}

// WithIdentity returns a new context containing the specified identity.
func WithIdentity(ctx context.Context, id IdentityContext) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext extracts the identity context from ctx.
func IdentityFromContext(ctx context.Context) (IdentityContext, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(identityContextKey{}).(IdentityContext)
	return id, ok
}

// IdentityCredential encapsulates authentication configuration for a single identity context.
// All secrets (tokens, passwords, cookies) are omitted from JSON serialization to prevent credential leaks.
type IdentityCredential struct {
	ID            IdentityContext   `json:"id"`
	Role          PersonaRole       `json:"role"`
	AuthMethod    AuthMethod        `json:"auth_method"`
	Username      string            `json:"username,omitempty"`
	BearerToken   string            `json:"-"`
	HeaderName    string            `json:"-"`
	HeaderValue   string            `json:"-"`
	Cookies       []*http.Cookie    `json:"-"`
	CookieJar     http.CookieJar    `json:"-"`
	CustomHeaders map[string]string `json:"-"`
}

// Summary provides a safe, redacted metadata representation of an identity credential.
type IdentityCredentialSummary struct {
	ID          IdentityContext `json:"id"`
	Role        PersonaRole     `json:"role"`
	AuthMethod  AuthMethod      `json:"auth_method"`
	Username    string          `json:"username,omitempty"`
	HasBearer   bool            `json:"has_bearer"`
	HasHeader   bool            `json:"has_header"`
	HasCookies  bool            `json:"has_cookies"`
	CookieCount int             `json:"cookie_count"`
}

// Summary returns safe metadata without cleartext credentials.
func (c *IdentityCredential) Summary() IdentityCredentialSummary {
	if c == nil {
		return IdentityCredentialSummary{ID: IdentityUnauthenticated, AuthMethod: AuthMethodNone}
	}
	return IdentityCredentialSummary{
		ID:          c.ID,
		Role:        c.Role,
		AuthMethod:  c.AuthMethod,
		Username:    c.Username,
		HasBearer:   c.BearerToken != "",
		HasHeader:   c.HeaderName != "" && c.HeaderValue != "",
		HasCookies:  len(c.Cookies) > 0 || c.CookieJar != nil,
		CookieCount: len(c.Cookies),
	}
}

// EffectivePort returns explicit port or default scheme port for an HTTP/HTTPS URL.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// IsSameOrigin checks whether two URLs share the exact scheme, host, and effective port.
func IsSameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) {
		return false
	}
	if !strings.EqualFold(u1.Hostname(), u2.Hostname()) {
		return false
	}
	return EffectivePort(u1) == EffectivePort(u2)
}

// IsLoopbackURL checks whether a URL's hostname resolves to loopback.
func IsLoopbackURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// AuthenticatedTransport wraps an http.RoundTripper with identity-aware authentication,
// strict origin credential confinement, and leakage protection across redirects and protocol downgrades.
type AuthenticatedTransport struct {
	base            http.RoundTripper
	allowedOrigin   *url.URL
	scopeAllowed    func(string) bool
	allowLoopback   bool
	allowPrivate    bool
	defaultIdentity IdentityContext
	mu              sync.RWMutex
	identities      map[IdentityContext]*IdentityCredential

	// Metrics
	dispatchedRequests int64
	authInjectedCount  int64
	crossOriginStripped int64
	downgradeStripped  int64
}

// AuthenticatedTransportOptions configures the authenticated transport.
type AuthenticatedTransportOptions struct {
	BaseTransport      http.RoundTripper
	TargetURL          string
	ScopeAllowed       func(string) bool
	AllowLoopback      bool
	AllowPrivate       bool
	InsecureSkipVerify bool
	DefaultIdentity    IdentityContext
}

// NewAuthenticatedTransport constructs a secure, identity-isolated transport.
func NewAuthenticatedTransport(opts AuthenticatedTransportOptions) (*AuthenticatedTransport, error) {
	parsedOrigin, err := url.Parse(opts.TargetURL)
	if err != nil || parsedOrigin.Host == "" {
		return nil, fmt.Errorf("invalid target URL for authenticated transport: %v", err)
	}

	base := opts.BaseTransport
	if base == nil {
		base = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: opts.InsecureSkipVerify,
			},
			DialContext: crawler.NewSafeDialContext(crawler.SafeDialerOptions{
				Timeout:         15 * time.Second,
				AllowLoopback:   opts.AllowLoopback,
				AllowPrivateIPs: opts.AllowPrivate,
			}),
		}
	}

	defaultID := opts.DefaultIdentity
	if defaultID == "" {
		defaultID = IdentityUnauthenticated
	}

	return &AuthenticatedTransport{
		base:            base,
		allowedOrigin:   parsedOrigin,
		scopeAllowed:    opts.ScopeAllowed,
		allowLoopback:   opts.AllowLoopback,
		allowPrivate:    opts.AllowPrivate,
		defaultIdentity: defaultID,
		identities:      make(map[IdentityContext]*IdentityCredential),
	}, nil
}

// SetIdentityCredential registers or updates an identity's credential configuration.
func (t *AuthenticatedTransport) SetIdentityCredential(cred IdentityCredential) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Ensure identity has an isolated cookie jar if none provided
	if cred.CookieJar == nil {
		jar, _ := cookiejar.New(nil)
		cred.CookieJar = jar
	}

	// Copy custom headers map defensively
	headersCopy := make(map[string]string)
	for k, v := range cred.CustomHeaders {
		headersCopy[k] = v
	}
	cred.CustomHeaders = headersCopy

	t.identities[cred.ID] = &cred
}

// GetIdentityCredential safely retrieves a registered identity's credential.
func (t *AuthenticatedTransport) GetIdentityCredential(id IdentityContext) (*IdentityCredential, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	cred, ok := t.identities[id]
	return cred, ok
}

// SetDefaultIdentity sets the fallback identity context used when none is provided in the request context.
func (t *AuthenticatedTransport) SetDefaultIdentity(id IdentityContext) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.defaultIdentity = id
}

// DefaultIdentity returns the current fallback identity context.
func (t *AuthenticatedTransport) DefaultIdentity() IdentityContext {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.defaultIdentity
}

// RoundTrip executes an HTTP request with identity-isolated credential injection and leakage safeguards.
func (t *AuthenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	atomic.AddInt64(&t.dispatchedRequests, 1)

	// 1. Enforce Scope: Disallow out-of-scope targets before transmitting any bytes
	if t.scopeAllowed != nil && req.URL != nil && req.URL.String() != "" {
		if !t.scopeAllowed(req.URL.String()) {
			return nil, fmt.Errorf("SSRF / scope refusal: destination %s is outside permitted assessment scope", req.URL.String())
		}
	}

	// 2. Clone request defensively to guarantee concurrency safety and prevent mutation bleeding
	cloned := req.Clone(req.Context())

	// 3. Determine active identity context
	t.mu.RLock()
	activeID, hasID := IdentityFromContext(cloned.Context())
	if !hasID || activeID == "" {
		activeID = t.defaultIdentity
	}
	cred := t.identities[activeID]
	allowedOrigin := t.allowedOrigin
	t.mu.RUnlock()

	// 4. Credential Leakage Prevention Gate A: Origin Verification
	// Never forward credentials to unrelated external origins or different hosts/ports
	isTargetOrigin := IsSameOrigin(cloned.URL, allowedOrigin)
	isLoopbackSamePort := t.allowLoopback && IsLoopbackURL(cloned.URL) && IsLoopbackURL(allowedOrigin) && EffectivePort(cloned.URL) == EffectivePort(allowedOrigin)

	// If destination is not same-origin (and not explicitly allowed same-port loopback), strip all credentials
	if !isTargetOrigin && !isLoopbackSamePort {
		atomic.AddInt64(&t.crossOriginStripped, 1)
		cloned.Header.Del("Authorization")
		cloned.Header.Del("Proxy-Authorization")
		cloned.Header.Del("Cookie")
		return t.base.RoundTrip(cloned)
	}

	// 5. Credential Leakage Prevention Gate B: Protocol Downgrade Protection
	// If base target was HTTPS, never send credentials over an unencrypted HTTP connection
	if allowedOrigin != nil && strings.EqualFold(allowedOrigin.Scheme, "https") && strings.EqualFold(cloned.URL.Scheme, "http") {
		if !isLoopbackSamePort {
			atomic.AddInt64(&t.downgradeStripped, 1)
			cloned.Header.Del("Authorization")
			cloned.Header.Del("Proxy-Authorization")
			cloned.Header.Del("Cookie")
			return t.base.RoundTrip(cloned)
		}
	}

	// 6. Identity Context Injection
	switch activeID {
	case IdentityUnauthenticated:
		// Strict Negative Control: Unauthenticated requests contain zero credentials
		cloned.Header.Del("Authorization")
		cloned.Header.Del("Proxy-Authorization")
		cloned.Header.Del("Cookie")

	default:
		// Authenticated contexts: User A, User B, Admin
		if cred != nil {
			// A. Bearer Token Injection
			// Only inject if request does not already carry an explicit Authorization header
			if cred.BearerToken != "" && cloned.Header.Get("Authorization") == "" {
				token := strings.TrimSpace(cred.BearerToken)
				if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
					token = "Bearer " + token
				}
				cloned.Header.Set("Authorization", token)
				atomic.AddInt64(&t.authInjectedCount, 1)
			}

			// B. Custom Authentication Header Injection
			if cred.HeaderName != "" && cred.HeaderValue != "" && cloned.Header.Get(cred.HeaderName) == "" {
				cloned.Header.Set(cred.HeaderName, cred.HeaderValue)
			}

			// C. Custom Headers Map
			for k, v := range cred.CustomHeaders {
				if cloned.Header.Get(k) == "" {
					cloned.Header.Set(k, v)
				}
			}

			// D. Isolated Cookie Jar Injection (Strict Domain and Path scoping)
			if cred.CookieJar != nil && cloned.URL != nil {
				cookies := cred.CookieJar.Cookies(cloned.URL)
				for _, c := range cookies {
					cloned.AddCookie(c)
				}
			}

			// E. Static Scoped Cookies
			for _, c := range cred.Cookies {
				if cookieMatchesScope(c, cloned.URL) {
					cloned.AddCookie(c)
				}
			}
		}
	}

	// 7. Execute outbound RoundTrip via base transport
	resp, err := t.base.RoundTrip(cloned)
	if err != nil {
		return nil, err
	}

	// 8. Capture Set-Cookie headers into identity's isolated CookieJar
	if resp != nil && cred != nil && cred.CookieJar != nil && cloned.URL != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			cred.CookieJar.SetCookies(cloned.URL, rc)
		}
	}

	return resp, nil
}

// cookieMatchesScope checks if a cookie is valid for the target URL's domain, path, and scheme.
func cookieMatchesScope(c *http.Cookie, u *url.URL) bool {
	if c == nil || u == nil {
		return false
	}

	// 1. Secure flag enforcement
	if c.Secure && !strings.EqualFold(u.Scheme, "https") && !IsLoopbackURL(u) {
		return false
	}

	// 2. Domain matching
	reqHost := strings.ToLower(u.Hostname())
	cookieDomain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))

	if cookieDomain != "" {
		if reqHost != cookieDomain && !strings.HasSuffix(reqHost, "."+cookieDomain) {
			return false
		}
	}

	// 3. Path matching
	if c.Path != "" && c.Path != "/" {
		reqPath := u.Path
		if reqPath == "" {
			reqPath = "/"
		}
		if !strings.HasPrefix(reqPath, c.Path) {
			return false
		}
	}

	return true
}

// IdentityManager coordinates identity definitions, credential ingestion,
// and creation of identity-bound HTTP clients for the assessment pipeline.
type IdentityManager struct {
	mu            sync.RWMutex
	targetURL     string
	parsedURL     *url.URL
	scopeAllowed  func(string) bool
	allowLoopback bool
	allowPrivate  bool
	timeout       time.Duration
	transport     *AuthenticatedTransport
	identities    map[IdentityContext]*IdentityCredential
}

// IdentityManagerOptions configures the IdentityManager.
type IdentityManagerOptions struct {
	TargetURL          string
	ScopeAllowed       func(string) bool
	AllowLoopback      bool
	AllowPrivate       bool
	InsecureSkipVerify bool
	Timeout            time.Duration
	DefaultIdentity    IdentityContext
}

// NewIdentityManager initializes an IdentityManager for a target URL.
func NewIdentityManager(opts IdentityManagerOptions) (*IdentityManager, error) {
	parsed, err := url.Parse(opts.TargetURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}

	transport, err := NewAuthenticatedTransport(AuthenticatedTransportOptions{
		TargetURL:          opts.TargetURL,
		ScopeAllowed:       opts.ScopeAllowed,
		AllowLoopback:      opts.AllowLoopback,
		AllowPrivate:       opts.AllowPrivate,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		DefaultIdentity:    opts.DefaultIdentity,
	})
	if err != nil {
		return nil, err
	}

	mgr := &IdentityManager{
		targetURL:     opts.TargetURL,
		parsedURL:     parsed,
		scopeAllowed:  opts.ScopeAllowed,
		allowLoopback: opts.AllowLoopback,
		allowPrivate:  opts.AllowPrivate,
		timeout:       opts.Timeout,
		transport:     transport,
		identities:    make(map[IdentityContext]*IdentityCredential),
	}

	// Register default unauthenticated identity
	mgr.ConfigureIdentity(IdentityCredential{
		ID:         IdentityUnauthenticated,
		Role:       RoleAnonymous,
		AuthMethod: AuthMethodNone,
	})

	return mgr, nil
}

// ConfigureIdentity registers or updates an identity context.
func (m *IdentityManager) ConfigureIdentity(cred IdentityCredential) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cred.CookieJar == nil {
		jar, _ := cookiejar.New(nil)
		cred.CookieJar = jar
	}

	m.identities[cred.ID] = &cred
	m.transport.SetIdentityCredential(cred)
}

// SetBearerToken configures a Bearer token credential for an identity.
func (m *IdentityManager) SetBearerToken(id IdentityContext, role PersonaRole, token string) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	m.ConfigureIdentity(IdentityCredential{
		ID:          id,
		Role:        role,
		AuthMethod:  AuthMethodBearer,
		BearerToken: token,
	})
}

// SetCookie configures a session cookie for an identity.
func (m *IdentityManager) SetCookie(id IdentityContext, role PersonaRole, rawCookie string) error {
	m.mu.Lock()
	cred, ok := m.identities[id]
	if !ok {
		jar, _ := cookiejar.New(nil)
		cred = &IdentityCredential{
			ID:         id,
			Role:       role,
			AuthMethod: AuthMethodHeader,
			CookieJar:  jar,
		}
		m.identities[id] = cred
	}
	m.mu.Unlock()

	// Parse cookie header
	fakeHeader := http.Header{"Set-Cookie": []string{rawCookie}}
	fakeResp := http.Response{Header: fakeHeader}
	parsed := fakeResp.Cookies()
	if len(parsed) == 0 {
		// Attempt direct key=val parse
		parts := strings.SplitN(rawCookie, "=", 2)
		if len(parts) == 2 {
			c := &http.Cookie{
				Name:  strings.TrimSpace(parts[0]),
				Value: strings.TrimSpace(parts[1]),
				Path:  "/",
			}
			parsed = []*http.Cookie{c}
		} else {
			return fmt.Errorf("invalid cookie format: %s", rawCookie)
		}
	}

	cred.CookieJar.SetCookies(m.parsedURL, parsed)
	cred.Cookies = append(cred.Cookies, parsed...)
	m.transport.SetIdentityCredential(*cred)
	return nil
}

// RolesConfigFileContent represents the flexible JSON format supported by --roles-config.
type RolesConfigFileContent struct {
	UserA any `json:"user_a"`
	UserB any `json:"user_b"`
	Admin any `json:"admin"`
	Auth  any `json:"auth"`
}

// LoadRolesConfig parses a role configuration file supporting both string tokens and structured maps.
func (m *IdentityManager) LoadRolesConfig(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read roles config file %q: %w", filePath, err)
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return fmt.Errorf("failed to parse roles config JSON: %w", err)
	}

	parseEntry := func(id IdentityContext, role PersonaRole, raw json.RawMessage) {
		if len(raw) == 0 {
			return
		}
		// Try string first
		var strVal string
		if err := json.Unmarshal(raw, &strVal); err == nil && strVal != "" {
			m.SetBearerToken(id, role, strVal)
			return
		}

		// Try structured object
		var objVal struct {
			Role       string            `json:"role"`
			Token      string            `json:"token"`
			AuthToken  string            `json:"auth_token"`
			Bearer     string            `json:"bearer"`
			AuthMethod string            `json:"auth_method"`
			Cookie     string            `json:"cookie"`
			Cookies    string            `json:"cookies"`
			Username   string            `json:"username"`
			Headers    map[string]string `json:"headers"`
		}
		if err := json.Unmarshal(raw, &objVal); err == nil {
			effectiveRole := role
			if strings.TrimSpace(objVal.Role) != "" {
				effectiveRole = PersonaRole(strings.TrimSpace(objVal.Role))
			}
			tok := objVal.Token
			if tok == "" {
				tok = objVal.AuthToken
			}
			if tok == "" {
				tok = objVal.Bearer
			}
			if tok != "" {
				m.SetBearerToken(id, effectiveRole, tok)
			}
			cookieStr := objVal.Cookie
			if cookieStr == "" {
				cookieStr = objVal.Cookies
			}
			if cookieStr != "" {
				_ = m.SetCookie(id, effectiveRole, cookieStr)
			}
			if len(objVal.Headers) > 0 || objVal.Username != "" {
				m.mu.Lock()
				cred, exists := m.identities[id]
				if !exists && (len(objVal.Headers) > 0 || objVal.Username != "") {
					jar, _ := cookiejar.New(nil)
					cred = &IdentityCredential{
						ID:         id,
						Role:       effectiveRole,
						AuthMethod: AuthMethodHeader,
						CookieJar:  jar,
					}
					m.identities[id] = cred
				}
				if cred != nil {
					cred.Role = effectiveRole
					if objVal.Username != "" {
						cred.Username = objVal.Username
					}
					if len(objVal.Headers) > 0 {
						if cred.CustomHeaders == nil {
							cred.CustomHeaders = make(map[string]string)
						}
						for k, v := range objVal.Headers {
							cred.CustomHeaders[k] = v
						}
					}
					m.transport.SetIdentityCredential(*cred)
				}
				m.mu.Unlock()
			}
		}
	}

	if raw, ok := rawMap["user_a"]; ok {
		parseEntry(IdentityUserA, RoleVictim, raw)
	}
	if raw, ok := rawMap["user_b"]; ok {
		parseEntry(IdentityUserB, RoleAttacker, raw)
	}
	if raw, ok := rawMap["admin"]; ok {
		parseEntry(IdentityAdmin, RoleAdmin, raw)
	}
	if raw, ok := rawMap["auth"]; ok {
		parseEntry(IdentityUserA, RoleVictim, raw)
	}

	return nil
}

// BuildClient creates an http.Client bound to this manager's transport with strict redirect security.
func (m *IdentityManager) BuildClient(defaultID IdentityContext) *http.Client {
	scopeAllowed := m.scopeAllowed
	allowLoopback := m.allowLoopback
	allowPrivate := m.allowPrivate
	allowedOrigin := m.parsedURL

	var tr http.RoundTripper = m.transport
	if defaultID != "" {
		// When a client is dedicated to a specific identity, wrap RoundTripper to guarantee context tagging
		tr = &identityBoundTransport{
			inner:    m.transport,
			identity: defaultID,
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   m.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 1. Max redirects & URL scheme/userinfo safety
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect to disallowed scheme %q blocked", req.URL.Scheme)
			}
			if req.URL.User != nil {
				return fmt.Errorf("redirect containing embedded userinfo blocked")
			}

			// 2. Scope policy validation
			if scopeAllowed != nil && !scopeAllowed(req.URL.String()) {
				return fmt.Errorf("redirect to out-of-scope destination %s blocked by policy", req.URL.String())
			}

			// 3. Prohibited IP / SSRF validation
			redirHost := req.URL.Hostname()
			redirIPs, _ := net.LookupIP(redirHost)
			for _, rip := range redirIPs {
				if prohibited, reason := crawler.ProhibitedIPReason(rip, allowLoopback, allowPrivate); prohibited {
					return fmt.Errorf("redirect to prohibited destination %s (%s: %s) blocked", req.URL.String(), rip.String(), reason)
				}
			}

			// 4. Credential Leakage Prevention across Redirects:
			// Strip Authorization and Cookie headers if redirect target is cross-origin or downgraded
			isTargetOrigin := IsSameOrigin(req.URL, allowedOrigin)
			isLoopbackSamePort := allowLoopback && IsLoopbackURL(req.URL) && IsLoopbackURL(allowedOrigin) && EffectivePort(req.URL) == EffectivePort(allowedOrigin)

			if !isTargetOrigin && !isLoopbackSamePort {
				req.Header.Del("Authorization")
				req.Header.Del("Proxy-Authorization")
				req.Header.Del("Cookie")
			}

			// HTTPS-to-HTTP downgrade strip
			if len(via) > 0 && strings.EqualFold(via[len(via)-1].URL.Scheme, "https") && strings.EqualFold(req.URL.Scheme, "http") {
				if !isLoopbackSamePort {
					req.Header.Del("Authorization")
					req.Header.Del("Proxy-Authorization")
					req.Header.Del("Cookie")
				}
			}

			return nil
		},
	}
}

// ClientFor returns an http.Client pre-configured to execute requests under the specified identity.
func (m *IdentityManager) ClientFor(id IdentityContext) *http.Client {
	return m.BuildClient(id)
}

// Transport returns the underlying AuthenticatedTransport.
func (m *IdentityManager) Transport() *AuthenticatedTransport {
	return m.transport
}

// identityBoundTransport injects an identity into the request context before forwarding to the AuthenticatedTransport.
type identityBoundTransport struct {
	inner    http.RoundTripper
	identity IdentityContext
}

func (t *identityBoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if _, ok := IdentityFromContext(ctx); !ok {
		ctx = WithIdentity(ctx, t.identity)
		req = req.WithContext(ctx)
	}
	return t.inner.RoundTrip(req)
}

// AuthVerificationResult details the outcome of live credential verification on the target.
type AuthVerificationResult struct {
	Identity       IdentityContext `json:"identity"`
	Verified       bool            `json:"verified"`
	StatusCode     int             `json:"status_code"`
	State          AuthState       `json:"state"`
	FailureReason  string          `json:"failure_reason,omitempty"`
	RedirectTarget string          `json:"redirect_target,omitempty"`
}

// VerifyIdentity tests whether an identity's credentials are accepted by the target.
func (m *IdentityManager) VerifyIdentity(ctx context.Context, id IdentityContext, probeEndpoint string) (*AuthVerificationResult, error) {
	targetURL := m.targetURL
	if probeEndpoint != "" {
		if strings.HasPrefix(probeEndpoint, "http://") || strings.HasPrefix(probeEndpoint, "https://") {
			targetURL = probeEndpoint
		} else {
			targetURL = strings.TrimRight(m.targetURL, "/") + "/" + strings.TrimLeft(probeEndpoint, "/")
		}
	}

	client := m.ClientFor(id)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Felix-AuthVerifier/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return &AuthVerificationResult{
			Identity:      id,
			Verified:      false,
			State:         AuthStateUnknown,
			FailureReason: fmt.Sprintf("Network connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	res := &AuthVerificationResult{
		Identity:   id,
		StatusCode: resp.StatusCode,
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
		res.Verified = true
		res.State = AuthStateConfirmed
	case http.StatusUnauthorized:
		res.Verified = false
		res.State = AuthStateExpiredConfirmed
		res.FailureReason = "Target returned HTTP 401 Unauthorized (invalid or expired credentials)"
	case http.StatusForbidden:
		res.Verified = false
		res.State = AuthStateExpiredConfirmed
		res.FailureReason = "Target returned HTTP 403 Forbidden (credential lacks access to route)"
	default:
		// Check redirect to login
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			loc := resp.Header.Get("Location")
			res.RedirectTarget = loc
			if strings.Contains(strings.ToLower(loc), "login") || strings.Contains(strings.ToLower(loc), "signin") {
				res.Verified = false
				res.State = AuthStateExpiredConfirmed
				res.FailureReason = fmt.Sprintf("Session rejected: redirected to login page (%s)", loc)
			} else {
				res.Verified = true
				res.State = AuthStateConfirmed
			}
		} else {
			res.Verified = true
			res.State = AuthStateConfirmed
		}
	}

	return res, nil
}

// RedactAuthHeader redacts sensitive headers for logging and reporting.
func RedactAuthHeader(key, val string) string {
	lower := strings.ToLower(key)
	if lower == "authorization" || lower == "proxy-authorization" || lower == "x-auth-token" || lower == "x-api-key" {
		return "[REDACTED]"
	}
	if lower == "cookie" || lower == "set-cookie" {
		return secrets.RedactCookieHeader(val)
	}
	return secrets.RedactText(val)
}
