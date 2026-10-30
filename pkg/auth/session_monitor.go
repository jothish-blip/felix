package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

var (
	ErrMonitorClosed       = errors.New("session monitor is closed")
	ErrNoMacroConfigured   = errors.New("no login macro configured for session monitor")
	ErrSessionExpired      = errors.New("session is expired")
	ErrInvalidSessionState = errors.New("invalid session state returned by login macro")
	ErrHealthCheckFailed   = errors.New("authenticated health check failed")
)

// SessionMonitorConfig defines the configuration and operational parameters
// for the session keep-alive and singleflight auto-refresh monitor.
type SessionMonitorConfig struct {
	Name              string
	Macro             *LoginMacro
	HealthCheckURL    string
	HealthCheckFn     func(ctx context.Context, client *http.Client) (bool, error)
	KeepAliveInterval time.Duration
	SessionMaxAge     time.Duration
	RefreshTimeout    time.Duration
	IsExpiredFunc     func(resp *http.Response, body []byte) bool
}

// SessionMonitorMetrics reports atomic runtime execution counters.
type SessionMonitorMetrics struct {
	MacroExecutions     int64 `json:"macro_executions"`
	RefreshRequests     int64 `json:"refresh_requests"`
	SuccessfulRefreshes int64 `json:"successful_refreshes"`
	FailedRefreshes     int64 `json:"failed_refreshes"`
	ReusedSessions      int64 `json:"reused_sessions"`
}

// SessionMonitor coordinates session keep-alive, expiration detection, and
// singleflight re-authentication across concurrent workers.
//
// Shared Session Safety and Ownership:
// MacroSession instances returned by SessionMonitor are shared across concurrent
// workers. Callers must treat the returned session, its cookie jar, and metadata as
// read-only. Callers must NOT mutate cookies, session properties, or the shared
// http.Client directly. For authenticated requests with automatic retry on expiration,
// callers should use SessionMonitor.Do().
type SessionMonitor struct {
	cfg      SessionMonitorConfig
	mu       sync.RWMutex
	current  *MacroSession
	sfGroup  singleflight.Group
	ctx      context.Context
	cancel   context.CancelFunc
	closeCh  chan struct{}
	stopOnce sync.Once
	closed   bool

	// Atomic counters for concurrency metrics
	macroExecutions     int64
	refreshRequests     int64
	successfulRefreshes int64
	failedRefreshes     int64
	reusedSessions      int64
}

// NewSessionMonitor creates an active session monitor from configuration.
func NewSessionMonitor(cfg SessionMonitorConfig) *SessionMonitor {
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = 15 * time.Second
	}
	if cfg.SessionMaxAge <= 0 {
		cfg.SessionMaxAge = 30 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm := &SessionMonitor{
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		closeCh: make(chan struct{}),
	}

	if cfg.KeepAliveInterval > 0 && (cfg.HealthCheckURL != "" || cfg.HealthCheckFn != nil) {
		go sm.keepAliveLoop()
	}

	return sm
}

// GetSession returns the current valid authenticated session.
// If the current session is nil or expired, it initiates a singleflight refresh.
func (m *SessionMonitor) GetSession(ctx context.Context) (*MacroSession, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrMonitorClosed
	}

	if m.current != nil && m.current.Authenticated && !m.isExpiredLocked(m.current) {
		sess := m.current
		m.mu.RUnlock()
		atomic.AddInt64(&m.reusedSessions, 1)
		return sess, nil
	}
	m.mu.RUnlock()

	return m.RefreshSession(ctx, "session_missing_or_expired")
}

// CurrentSession returns the currently stored session without triggering a refresh.
func (m *SessionMonitor) CurrentSession() *MacroSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// SetSession manually sets the current authenticated session.
func (m *SessionMonitor) SetSession(sess *MacroSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = sess
}

// RefreshSession coordinates concurrent re-login requests.
// When multiple goroutines invoke RefreshSession simultaneously, singleflight.Group
// guarantees that exactly ONE login macro execution occurs. All waiting goroutines
// receive the identical refreshed MacroSession.
//
// Shared Refresh Cancellation Guarantee:
// The singleflight execution runs under a bounded context rooted in the monitor's
// lifecycle, not an individual caller's context. A single caller's cancellation
// will abort that caller's wait without terminating the refresh needed by other
// concurrent callers.
func (m *SessionMonitor) RefreshSession(ctx context.Context, reason string) (*MacroSession, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrMonitorClosed
	}
	m.mu.RUnlock()

	atomic.AddInt64(&m.refreshRequests, 1)

	// Capture the ID of the session that triggered this refresh
	m.mu.RLock()
	triggerSessionID := ""
	if m.current != nil {
		triggerSessionID = m.current.ID
	}
	m.mu.RUnlock()

	ch := m.sfGroup.DoChan("session_refresh", func() (any, error) {
		// Double-check under read lock: was a newer valid session installed while
		// waiting to enter the singleflight operation?
		m.mu.RLock()
		if m.current != nil && m.current.Authenticated && !m.isExpiredLocked(m.current) {
			if triggerSessionID != "" && m.current.ID != triggerSessionID {
				cached := m.current
				m.mu.RUnlock()
				return cached, nil
			}
		}
		m.mu.RUnlock()

		if m.cfg.Macro == nil {
			atomic.AddInt64(&m.failedRefreshes, 1)
			return nil, ErrNoMacroConfigured
		}

		// Shared bounded refresh context derived from monitor root context
		refreshTimeout := m.cfg.RefreshTimeout
		if refreshTimeout <= 0 {
			refreshTimeout = 15 * time.Second
		}
		execCtx, execCancel := context.WithTimeout(m.ctx, refreshTimeout)
		defer execCancel()

		// Record the actual macro execution invocation
		atomic.AddInt64(&m.macroExecutions, 1)

		// Execute the login macro with ZERO locks held to prevent lock contention
		newSession, err := m.cfg.Macro.Execute(execCtx)
		if err != nil {
			atomic.AddInt64(&m.failedRefreshes, 1)
			return nil, fmt.Errorf("session refresh macro execution failed: %w", err)
		}

		if newSession == nil || !newSession.Authenticated {
			atomic.AddInt64(&m.failedRefreshes, 1)
			return nil, ErrInvalidSessionState
		}

		// Atomically update current session under write lock
		m.mu.Lock()
		// Guard against stale results replacing newer sessions
		if m.current == nil || !newSession.AuthenticatedAt.Before(m.current.AuthenticatedAt) {
			m.current = newSession
		}
		m.mu.Unlock()

		return newSession, nil
	})

	// Wait on either the individual caller's context, monitor shutdown, or singleflight channel
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.closeCh:
		return nil, ErrMonitorClosed
	case res, ok := <-ch:
		if !ok {
			return nil, ErrMonitorClosed
		}
		if res.Err != nil {
			return nil, res.Err
		}
		session, ok := res.Val.(*MacroSession)
		if !ok || session == nil {
			return nil, ErrInvalidSessionState
		}
		atomic.AddInt64(&m.successfulRefreshes, 1)
		return session, nil
	}
}

// InvalidateSession safely invalidates the current session.
// If sessionID is specified and does not match m.current.ID, the invalidation is
// ignored as a stale event, preventing older workers from wiping out a freshly
// refreshed session.
func (m *SessionMonitor) InvalidateSession(sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.current == nil {
		return false
	}
	if sessionID != "" && m.current.ID != sessionID {
		// Stale invalidation: session was already updated to a newer ID
		return false
	}
	m.current = nil
	return true
}

// IsSessionExpired checks whether an HTTP response indicates session expiration.
// - HTTP 401 Unauthorized: universally indicates authentication failure.
// - HTTP 302/303/307 Redirects: indicates expiration if redirecting to a login page.
// - HTTP 403 Forbidden: treated carefully. Only treated as expiration if explicit
//   headers/indicators indicate session death, avoiding false refreshes during
//   deliberate authorization / BOLA fuzzing probes.
func (m *SessionMonitor) IsSessionExpired(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	if m.cfg.IsExpiredFunc != nil {
		return m.cfg.IsExpiredFunc(resp, nil)
	}

	// 1. 401 Unauthorized is always an authentication failure
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}

	// 2. Redirect to login form
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect {
		loc := resp.Header.Get("Location")
		if loc != "" {
			locLower := strings.ToLower(loc)
			if strings.Contains(locLower, "login") || strings.Contains(locLower, "signin") || strings.Contains(locLower, "auth") {
				return true
			}
			if m.cfg.Macro != nil && m.cfg.Macro.cfg.TargetURL != "" {
				u, err := url.Parse(m.cfg.Macro.cfg.TargetURL)
				if err == nil && u.Path != "" && strings.Contains(loc, u.Path) {
					return true
				}
			}
		}
	}

	// 3. 403 Forbidden: distinguish session death from authorization denial
	if resp.StatusCode == http.StatusForbidden {
		if resp.Header.Get("X-Session-Expired") == "true" {
			return true
		}
	}

	return false
}

// Do executes an HTTP request using the current authenticated session.
// If the response indicates session expiration, it invalidates the current session,
// triggers a singleflight refresh, and retries the request once.
func (m *SessionMonitor) Do(req *http.Request) (*http.Response, error) {
	sess, err := m.GetSession(req.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to obtain session: %w", err)
	}

	resp, err := sess.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if m.IsSessionExpired(resp) {
		// Drain and close expired response body before retry
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		m.InvalidateSession(sess.ID)
		freshSess, refErr := m.RefreshSession(req.Context(), "http_response_expired")
		if refErr != nil {
			return nil, fmt.Errorf("failed to refresh session after expiration: %w", refErr)
		}

		// Rewind request body if replayable
		if req.GetBody != nil {
			newBody, bErr := req.GetBody()
			if bErr == nil {
				req.Body = newBody
			}
		}

		return freshSess.Client.Do(req)
	}

	return resp, nil
}

// CheckHealth executes an explicit health check against the configured endpoint.
func (m *SessionMonitor) CheckHealth(ctx context.Context) (bool, error) {
	sess, err := m.GetSession(ctx)
	if err != nil {
		return false, err
	}

	if m.cfg.HealthCheckFn != nil {
		return m.cfg.HealthCheckFn(ctx, sess.Client)
	}

	if m.cfg.HealthCheckURL == "" {
		return true, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.HealthCheckURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build healthcheck request: %w", err)
	}
	req.Header.Set("User-Agent", "Felix-Security-Scanner/3.0")

	resp, err := sess.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer resp.Body.Close()

	if m.IsSessionExpired(resp) {
		m.InvalidateSession(sess.ID)
		return false, ErrHealthCheckFailed
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, nil
	}

	return false, fmt.Errorf("healthcheck returned unexpected status %d", resp.StatusCode)
}

// keepAliveLoop proactively verifies session validity at periodic intervals.
func (m *SessionMonitor) keepAliveLoop() {
	ticker := time.NewTicker(m.cfg.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.closeCh:
			return
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.RLock()
			hasSession := m.current != nil && m.current.Authenticated
			m.mu.RUnlock()

			if !hasSession {
				continue
			}

			alive, _ := m.CheckHealth(m.ctx)
			if !alive {
				_, _ = m.RefreshSession(m.ctx, "keepalive_tick_failed")
			}
		}
	}
}

// isExpiredLocked evaluates if the given session has exceeded SessionMaxAge.
// Must be called with m.mu held (either read or write).
func (m *SessionMonitor) isExpiredLocked(sess *MacroSession) bool {
	if sess == nil || !sess.Authenticated {
		return true
	}
	if m.cfg.SessionMaxAge > 0 && time.Since(sess.AuthenticatedAt) > m.cfg.SessionMaxAge {
		return true
	}
	return false
}

// Metrics returns snapshot copy of atomic execution counters.
func (m *SessionMonitor) Metrics() SessionMonitorMetrics {
	return SessionMonitorMetrics{
		MacroExecutions:     atomic.LoadInt64(&m.macroExecutions),
		RefreshRequests:     atomic.LoadInt64(&m.refreshRequests),
		SuccessfulRefreshes: atomic.LoadInt64(&m.successfulRefreshes),
		FailedRefreshes:     atomic.LoadInt64(&m.failedRefreshes),
		ReusedSessions:      atomic.LoadInt64(&m.reusedSessions),
	}
}

// Close gracefully stops background tasks and releases resources.
func (m *SessionMonitor) Close() error {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.cancel()
		close(m.closeCh)
	})
	return nil
}
