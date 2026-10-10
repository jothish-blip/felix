package authz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"time"
)

// PreflightSessionResult contains the health check status of an identity's active session.
type PreflightSessionResult struct {
	Alias        string `json:"alias"`
	Valid        bool   `json:"valid"`
	StatusCode   int    `json:"status_code"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// SessionManager manages isolated HTTP clients and cookie jars per identity alias,
// environment variable credential injection, and pre-flight session validation.
type SessionManager struct {
	timeout    time.Duration
	transport  http.RoundTripper
	clients    map[string]*http.Client
	cookieJars map[string]*cookiejar.Jar
	mu         sync.RWMutex
}

// NewSessionManager creates a new SessionManager with per-identity isolation.
func NewSessionManager(timeout time.Duration) *SessionManager {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &SessionManager{
		timeout:    timeout,
		clients:    make(map[string]*http.Client),
		cookieJars: make(map[string]*cookiejar.Jar),
	}
}

// SetTransport allows configuring a custom RoundTripper (e.g. for testing).
func (sm *SessionManager) SetTransport(rt http.RoundTripper) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.transport = rt
	for _, client := range sm.clients {
		client.Transport = rt
	}
}

// GetClientForIdentity returns an isolated http.Client with its own CookieJar for the specified identity alias.
func (sm *SessionManager) GetClientForIdentity(alias string) *http.Client {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := strings.ToLower(strings.TrimSpace(alias))
	if client, exists := sm.clients[key]; exists {
		return client
	}

	// Create an isolated cookie jar so sessions and cookies never bleed between identities
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: sm.timeout,
		Jar:     jar,
	}
	if sm.transport != nil {
		client.Transport = sm.transport
	}

	sm.clients[key] = client
	sm.cookieJars[key] = jar
	return client
}

// GetCookieJar returns the isolated cookie jar for a specific identity, if initialized.
func (sm *SessionManager) GetCookieJar(alias string) *cookiejar.Jar {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	key := strings.ToLower(strings.TrimSpace(alias))
	return sm.cookieJars[key]
}

// InjectEnvCredentials scans environment variables for tokens and cookies and injects them
// into policy identities using the pattern:
// FELIX_AUTH_<ALIAS>_TOKEN or FELIX_AUTH_<ALIAS>_BEARER -> Header: "Authorization: Bearer <token>"
// FELIX_AUTH_<ALIAS>_COOKIE -> Cookies
// FELIX_AUTH_<ALIAS>_HEADER_<KEY> -> Custom Header
func InjectEnvCredentials(policy *AuthzPolicy) {
	if policy == nil || policy.Identities == nil {
		return
	}

	for alias, id := range policy.Identities {
		envPrefix := "FELIX_AUTH_" + SanitizeEnvKey(alias) + "_"

		// 1. Token / Bearer
		token := os.Getenv(envPrefix + "TOKEN")
		if token == "" {
			token = os.Getenv(envPrefix + "BEARER")
		}
		if token != "" {
			if id.Headers == nil {
				id.Headers = make(map[string]string)
			}
			if !strings.HasPrefix(token, "Bearer ") {
				id.Headers["Authorization"] = "Bearer " + token
			} else {
				id.Headers["Authorization"] = token
			}
		}

		// 2. Cookie string
		cookieStr := os.Getenv(envPrefix + "COOKIE")
		if cookieStr != "" {
			if id.Cookies == nil {
				id.Cookies = make(map[string]string)
			}
			// Parse cookie string e.g. "session_id=abc; other=xyz"
			parts := strings.Split(cookieStr, ";")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
					id.Cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				} else if len(kv) == 1 && kv[0] != "" {
					id.Cookies["session"] = strings.TrimSpace(kv[0])
				}
			}
		}

		// 3. Custom headers (e.g. FELIX_AUTH_<ALIAS>_HEADER_X_API_KEY)
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, envPrefix+"HEADER_") {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) == 2 {
					hdrKey := strings.TrimPrefix(parts[0], envPrefix+"HEADER_")
					hdrKey = http.CanonicalHeaderKey(strings.ReplaceAll(hdrKey, "_", "-"))
					if id.Headers == nil {
						id.Headers = make(map[string]string)
					}
					id.Headers[hdrKey] = parts[1]
				}
			}
		}

		policy.Identities[alias] = id
	}
}

// SanitizeEnvKey converts alias names like "user-a" or "user_a" to uppercase environment safe identifier "USER_A".
func SanitizeEnvKey(alias string) string {
	s := strings.ToUpper(alias)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

// VerifyIdentitySession conducts a pre-flight verification to establish whether an identity's
// session is currently authenticated and valid against checkURL.
func (sm *SessionManager) VerifyIdentitySession(
	ctx context.Context,
	alias string,
	id TestIdentity,
	checkURL string,
) PreflightSessionResult {
	res := PreflightSessionResult{
		Alias: alias,
	}

	client := sm.GetClientForIdentity(alias)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		res.Valid = false
		res.ErrorMessage = fmt.Sprintf("invalid check URL: %v", err)
		return res
	}

	// Apply identity headers
	for k, v := range id.Headers {
		req.Header.Set(k, v)
	}

	// Apply identity cookies
	for k, v := range id.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Valid = false
		res.ErrorMessage = fmt.Sprintf("preflight request failed: %v", err)
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode

	// 401 Unauthorized or 403 Forbidden indicates an invalid or expired session
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.Valid = false
		res.ErrorMessage = fmt.Sprintf("session expired or unauthorized (status %d)", resp.StatusCode)
		return res
	}

	// Server errors (500+)
	if resp.StatusCode >= 500 {
		res.Valid = false
		res.ErrorMessage = fmt.Sprintf("server error during preflight (status %d)", resp.StatusCode)
		return res
	}

	res.Valid = true
	return res
}

// PreflightAll verifies all identities in policy against their respective check URLs.
func (sm *SessionManager) PreflightAll(
	ctx context.Context,
	policy *AuthzPolicy,
	checkURLs map[string]string,
) map[string]PreflightSessionResult {
	results := make(map[string]PreflightSessionResult)
	if policy == nil || len(checkURLs) == 0 {
		return results
	}

	for alias, id := range policy.Identities {
		u, ok := checkURLs[alias]
		if !ok || u == "" {
			continue
		}
		res := sm.VerifyIdentitySession(ctx, alias, id, u)
		results[alias] = res
	}

	return results
}
