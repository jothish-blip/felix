package operator

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/config"
)

// Supported operator roles for role-based access control.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// IsValidRole reports whether role matches one of the recognized operator roles.
func IsValidRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

// DownloadToken represents a short-lived, narrowly scoped credential for safe browser report downloads.
type DownloadToken struct {
	Token        string    `json:"token"`
	AssessmentID string    `json:"assessment_id"`
	ReportID     string    `json:"report_id"`
	Format       string    `json:"format"` // "HTML", "JSON", or "*"
	ClientID     string    `json:"client_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Revoked      bool      `json:"revoked"`
}

// IsValid checks if the download token is unrevoked and not expired.
func (dt *DownloadToken) IsValid() bool {
	if dt == nil || dt.Revoked {
		return false
	}
	if !dt.ExpiresAt.IsZero() && time.Now().After(dt.ExpiresAt) {
		return false
	}
	return true
}

// Authorizes checks whether this download token is permitted for the given assessment, report, format, and client.
func (dt *DownloadToken) Authorizes(assessmentID, reportID, format, clientID string) bool {
	if !dt.IsValid() {
		return false
	}
	if dt.AssessmentID != "" && dt.AssessmentID != assessmentID {
		return false
	}
	if dt.ReportID != "" && dt.ReportID != reportID {
		return false
	}
	if dt.Format != "" && dt.Format != "*" && !strings.EqualFold(dt.Format, format) {
		return false
	}
	if dt.ClientID != "" && clientID != "" && dt.ClientID != clientID {
		return false
	}
	return true
}

type downloadTokenContextKey struct{}

func contextWithDownloadToken(ctx context.Context, dt *DownloadToken) context.Context {
	return context.WithValue(ctx, downloadTokenContextKey{}, dt)
}

// DownloadTokenFromContext retrieves a validated DownloadToken from request context if present.
func DownloadTokenFromContext(ctx context.Context) *DownloadToken {
	if v, ok := ctx.Value(downloadTokenContextKey{}).(*DownloadToken); ok {
		return v
	}
	return nil
}

// UserSession represents an authenticated operator session with role and tenant scope.
type UserSession struct {
	Token      string    `json:"token"`
	OperatorID string    `json:"operator_id"`
	Role       string    `json:"role"` // admin, operator, viewer
	ClientID   string    `json:"client_id,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Revoked    bool      `json:"revoked"`
}

// IsValid checks if the session is active, not revoked, and not expired.
func (s *UserSession) IsValid() bool {
	if s == nil || s.Revoked {
		return false
	}
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		return false
	}
	return true
}

// AuthContext returns the assessment.TenantAuthContext corresponding to this session.
func (s *UserSession) AuthContext() assessment.TenantAuthContext {
	if s == nil || !IsValidRole(s.Role) {
		return assessment.TenantAuthContext{}
	}
	if strings.EqualFold(s.Role, RoleAdmin) {
		return assessment.NewAdminAuthContext()
	}
	if s.ClientID == "" {
		return assessment.TenantAuthContext{}
	}
	return assessment.NewTenantAuthContext(s.ClientID, s.TenantID, "")
}

type contextKey string

const sessionContextKey contextKey = "felix.operator.session"

// contextWithSession returns a new context containing the given UserSession.
func contextWithSession(ctx context.Context, sess *UserSession) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}

// SessionFromContext extracts the authenticated UserSession from request context.
func SessionFromContext(ctx context.Context) *UserSession {
	if v, ok := ctx.Value(sessionContextKey).(*UserSession); ok {
		return v
	}
	return nil
}

// Config holds runtime parameters for the Felix Operator HTTP server.
type Config struct {
	ListenHost  string
	ListenPort  int
	OperatorID  string
	Token       string
	Store       assessment.Store
	JobManager  *assessment.JobManager
	Version     string
	ReportsRoot string // Optional override for report storage root
}

// Server provides the local-first HTTP interface for Felix Operator.
type Server struct {
	cfg        Config
	store      assessment.Store
	jobManager *assessment.JobManager
	httpServer *http.Server
	listener   net.Listener
	mux        *http.ServeMux
	token      string

	sessionsMu sync.RWMutex
	sessions   map[string]*UserSession

	downloadTokensMu sync.RWMutex
	downloadTokens   map[string]*DownloadToken

	allowedReportRootsMu sync.RWMutex
	allowedReportRoots   []string
}

// isLoopbackHost returns true if the host is a local loopback address.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" || h == "ip6-localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// GenerateSecureToken creates a cryptographically strong 32-byte hex token.
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewServer initializes the Felix Operator HTTP server, strictly validating loopback bindings.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("operator server requires a valid assessment.Store")
	}

	host := strings.TrimSpace(cfg.ListenHost)
	if host == "" {
		host = "127.0.0.1"
	}

	// Security Invariant: Bind strictly to loopback interface.
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf("security refusal: operator server must only bind to a loopback address (127.0.0.1 or ::1), got %q", host)
	}

	port := cfg.ListenPort
	if port <= 0 {
		port = 8383
	}

	opID := strings.TrimSpace(cfg.OperatorID)
	if opID == "" {
		opID = "operator"
	}

	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		var err error
		token, err = GenerateSecureToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secure operator token: %w", err)
		}
	}

	ver := strings.TrimSpace(cfg.Version)
	if ver == "" {
		ver = "2.0.0"
	}

	jm := cfg.JobManager
	if jm == nil {
		jm = assessment.NewJobManager(cfg.Store, nil)
	}

	s := &Server{
		cfg: Config{
			ListenHost:  host,
			ListenPort:  port,
			OperatorID:  opID,
			Token:       token,
			Store:       cfg.Store,
			JobManager:  jm,
			Version:     ver,
			ReportsRoot: cfg.ReportsRoot,
		},
		store:          cfg.Store,
		jobManager:     jm,
		mux:            http.NewServeMux(),
		token:          token,
		sessions:       make(map[string]*UserSession),
		downloadTokens: make(map[string]*DownloadToken),
	}

	if cfg.ReportsRoot != "" {
		s.AddAllowedReportsRoot(cfg.ReportsRoot)
	}
	if defaultDir, err := config.Dir(); err == nil && defaultDir != "" {
		s.AddAllowedReportsRoot(filepath.Join(defaultDir, "reports"))
	}

	s.sessions[token] = &UserSession{
		Token:      token,
		OperatorID: opID,
		Role:       RoleAdmin,
	}

	s.registerRoutes()
	return s, nil
}

// AddAllowedReportsRoot registers an authorized directory root for report storage.
func (s *Server) AddAllowedReportsRoot(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	s.allowedReportRootsMu.Lock()
	defer s.allowedReportRootsMu.Unlock()
	cleaned := filepath.Clean(dir)
	for _, existing := range s.allowedReportRoots {
		if existing == cleaned {
			return
		}
	}
	s.allowedReportRoots = append(s.allowedReportRoots, cleaned)
}

// validateReportPathContainment ensures that reportFilePath strictly resides inside an authorized report storage root.
// It defends against path traversal, absolute path injection, symlink escapes, and out-of-root files.
func (s *Server) validateReportPathContainment(reportFilePath string) (string, error) {
	if strings.TrimSpace(reportFilePath) == "" {
		return "", errors.New("report file path not recorded")
	}

	cleanedTarget := filepath.Clean(reportFilePath)

	// Resolve symlinks if file exists on disk
	resolvedTarget := cleanedTarget
	if realTarget, err := filepath.EvalSymlinks(cleanedTarget); err == nil {
		resolvedTarget = realTarget
	}

	s.allowedReportRootsMu.RLock()
	roots := make([]string, len(s.allowedReportRoots))
	copy(roots, s.allowedReportRoots)
	s.allowedReportRootsMu.RUnlock()

	// If no roots explicitly configured, default to Felix reports directory
	if len(roots) == 0 {
		if cfgDir, err := config.Dir(); err == nil && cfgDir != "" {
			roots = append(roots, filepath.Join(cfgDir, "reports"))
		}
	}

	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		if realRoot, err := filepath.EvalSymlinks(cleanRoot); err == nil {
			cleanRoot = realRoot
		}

		// Verify containment using filepath.Rel
		rel, err := filepath.Rel(cleanRoot, resolvedTarget)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return resolvedTarget, nil
		}
	}

	return "", fmt.Errorf("access denied: report file path is outside allowed storage directory")
}

// IssueDownloadToken issues a cryptographically random, short-lived download token (default 5 minutes)
// strictly scoped to a specific assessment, report, format, and client boundary.
func (s *Server) IssueDownloadToken(assessmentID, reportID, format, clientID string, ttl time.Duration) (*DownloadToken, error) {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secure download token: %w", err)
	}
	tokenStr := "dlt_" + hex.EncodeToString(tokenBytes)

	dt := &DownloadToken{
		Token:        tokenStr,
		AssessmentID: assessmentID,
		ReportID:     reportID,
		Format:       strings.ToUpper(format),
		ClientID:     clientID,
		ExpiresAt:    time.Now().UTC().Add(ttl),
		Revoked:      false,
	}

	s.downloadTokensMu.Lock()
	defer s.downloadTokensMu.Unlock()
	s.downloadTokens[tokenStr] = dt
	return dt, nil
}

// RevokeDownloadToken marks a download token as revoked.
func (s *Server) RevokeDownloadToken(token string) bool {
	s.downloadTokensMu.Lock()
	defer s.downloadTokensMu.Unlock()
	if dt, exists := s.downloadTokens[token]; exists {
		dt.Revoked = true
		return true
	}
	return false
}

// GetDownloadToken returns the active DownloadToken if valid, unrevoked, and unexpired.
func (s *Server) GetDownloadToken(token string) (*DownloadToken, bool) {
	s.downloadTokensMu.RLock()
	defer s.downloadTokensMu.RUnlock()
	dt, exists := s.downloadTokens[token]
	if !exists || !dt.IsValid() {
		return nil, false
	}
	return dt, true
}

// RegisterSession registers or updates an operator session.
func (s *Server) RegisterSession(sess *UserSession) error {
	if sess == nil || strings.TrimSpace(sess.Token) == "" {
		return errors.New("cannot register session with empty token")
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.sessions[sess.Token] = sess
	return nil
}

// RevokeSession marks a session token as revoked.
func (s *Server) RevokeSession(token string) bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if sess, exists := s.sessions[token]; exists {
		sess.Revoked = true
		return true
	}
	return false
}

// GetSession returns the active session for a given token, if valid.
func (s *Server) GetSession(token string) (*UserSession, bool) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	sess, exists := s.sessions[token]
	if !exists || !sess.IsValid() {
		return nil, false
	}
	return sess, true
}

func (s *Server) getSession(r *http.Request) *UserSession {
	return SessionFromContext(r.Context())
}

func (s *Server) getAuthContext(r *http.Request) assessment.TenantAuthContext {
	sess := s.getSession(r)
	if sess != nil {
		return sess.AuthContext()
	}
	if dt := DownloadTokenFromContext(r.Context()); dt != nil {
		if dt.ClientID != "" {
			return assessment.NewClientAuthContext(dt.ClientID)
		}
	}
	return assessment.TenantAuthContext{}
}

// requireRole verifies that the request has an authenticated session with one of the allowed roles.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, allowedRoles ...string) (*UserSession, bool) {
	sess := s.getSession(r)
	if sess == nil {
		s.respondError(w, http.StatusUnauthorized, "unauthorized: missing session")
		return nil, false
	}
	for _, allowed := range allowedRoles {
		if strings.EqualFold(sess.Role, allowed) {
			return sess, true
		}
	}
	s.respondError(w, http.StatusForbidden, fmt.Sprintf("forbidden: role %q lacks sufficient permissions", sess.Role))
	return sess, false
}

// requireAssessment fetches the assessment and verifies that caller's tenant context authorizes access.
func (s *Server) requireAssessment(w http.ResponseWriter, r *http.Request, assessmentID string) (*assessment.Assessment, bool) {
	if strings.TrimSpace(assessmentID) == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return nil, false
	}
	asm, err := s.store.GetAssessment(assessmentID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "assessment not found")
		return nil, false
	}
	authCtx := s.getAuthContext(r)
	if !authCtx.Authorizes(asm.ClientID, "", "") {
		// Fails closed with 404 to prevent IDOR enumeration of cross-tenant resource existence
		s.respondError(w, http.StatusNotFound, "assessment not found")
		return nil, false
	}
	return asm, true
}

// Token returns the active operator authentication token.
func (s *Server) Token() string {
	return s.token
}

// URL returns the local console URL including authentication token query.
func (s *Server) URL() string {
	addr := s.cfg.ListenHost
	if s.listener != nil {
		addr = s.listener.Addr().String()
		return fmt.Sprintf("http://%s/?token=%s", addr, s.token)
	}
	return fmt.Sprintf("http://%s:%d/?token=%s", addr, s.cfg.ListenPort, s.token)
}

// Start begins listening on the configured loopback address.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenHost, s.cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.httpServer = &http.Server{
		Handler:      s.buildMiddlewareChain(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	err = s.httpServer.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully terminates the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// buildMiddlewareChain wraps the root handler with security middlewares.
func (s *Server) buildMiddlewareChain(handler http.Handler) http.Handler {
	return s.securityHeaders(s.corsAndOriginValidation(s.authMiddleware(handler)))
}

// securityHeaders injects defense-in-depth security headers into all responses.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; connect-src 'self'; img-src 'self' data:;")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

// corsAndOriginValidation validates origins and blocks CSRF on state changes.
func (s *Server) corsAndOriginValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Handle CORS Preflight
		if r.Method == http.MethodOptions {
			if origin != "" {
				if s.isTrustedOrigin(origin) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Felix-Operator-Token, Authorization")
					w.WriteHeader(http.StatusNoContent)
					return
				}
				s.respondError(w, http.StatusForbidden, "forbidden: untrusted origin")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Mutating requests (POST, PUT, DELETE, PATCH) must originate from trusted origin
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if origin != "" {
				if !s.isTrustedOrigin(origin) {
					s.respondError(w, http.StatusForbidden, "forbidden: cross-origin mutation blocked")
					return
				}
			} else {
				// Fall back to Referer check if Origin is absent
				referer := r.Header.Get("Referer")
				if referer != "" {
					if !s.isTrustedOrigin(referer) {
						s.respondError(w, http.StatusForbidden, "forbidden: cross-origin referer blocked")
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) isTrustedOrigin(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return isLoopbackHost(host)
}

// authMiddleware enforces valid token for protected API endpoints.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean(r.URL.Path)

		// Non-API paths (static assets) and health check are public
		if !strings.HasPrefix(cleanPath, "/api/") || cleanPath == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		var token string

		// 1. Check header X-Felix-Operator-Token
		token = r.Header.Get("X-Felix-Operator-Token")

		// 2. Or Authorization: Bearer <token>
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		isDownloadRoute := strings.HasPrefix(cleanPath, "/api/v1/assessments/") &&
			(strings.HasSuffix(cleanPath, "/html") || strings.HasSuffix(cleanPath, "/json"))

		// Check for query token
		qToken := r.URL.Query().Get("download_token")
		if qToken == "" {
			qToken = r.URL.Query().Get("token")
		}

		if token == "" && qToken != "" {
			// Query parameter token presented.
			// Security Invariant: Query parameter authentication is strictly prohibited on mutating endpoints.
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
				s.respondError(w, http.StatusUnauthorized, "unauthorized: query parameter authentication is prohibited for mutating requests")
				return
			}

			// If it's a download route:
			if isDownloadRoute {
				// Query-string authentication on download routes requires a valid scoped DownloadToken
				dt, exists := s.GetDownloadToken(qToken)
				if !exists {
					// Check if token exists in raw issued tokens (to distinguish expired/revoked)
					s.downloadTokensMu.RLock()
					rawDt, wasIssued := s.downloadTokens[qToken]
					s.downloadTokensMu.RUnlock()
					if wasIssued && (rawDt.Revoked || (!rawDt.ExpiresAt.IsZero() && time.Now().After(rawDt.ExpiresAt))) {
						s.respondError(w, http.StatusUnauthorized, "unauthorized: expired or revoked download token")
						return
					}
					s.respondError(w, http.StatusUnauthorized, "unauthorized: invalid or missing download token")
					return
				}

				// Scoped DownloadToken is valid! Attach to context and continue.
				ctx := contextWithDownloadToken(r.Context(), dt)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Non-download route with query token:
			// Check if someone is trying to use a DownloadToken on a general API endpoint
			s.downloadTokensMu.RLock()
			_, isDt := s.downloadTokens[qToken]
			s.downloadTokensMu.RUnlock()
			if isDt {
				s.respondError(w, http.StatusForbidden, "forbidden: download token cannot be used for API endpoints")
				return
			}

			// For backwards compatibility with s.token in test environments on general GET routes:
			token = qToken
		}

		if token == "" {
			s.respondError(w, http.StatusUnauthorized, "unauthorized: missing operator token")
			return
		}

		// Look up session in registered sessions
		s.sessionsMu.RLock()
		sess, exists := s.sessions[token]
		s.sessionsMu.RUnlock()

		if !exists {
			// Fallback check against master s.token using constant-time comparison
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1 {
				sess = &UserSession{
					Token:      s.token,
					OperatorID: s.cfg.OperatorID,
					Role:       RoleAdmin,
				}
			} else {
				s.respondError(w, http.StatusUnauthorized, "unauthorized: invalid operator token")
				return
			}
		}

		if !sess.IsValid() {
			s.respondError(w, http.StatusUnauthorized, "unauthorized: expired or revoked operator token")
			return
		}

		if !IsValidRole(sess.Role) {
			s.respondError(w, http.StatusForbidden, fmt.Sprintf("forbidden: role %q lacks sufficient permissions", sess.Role))
			return
		}

		// Inject verified session into request context
		ctx := contextWithSession(r.Context(), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// respondJSON writes a JSON response with status code.
func (s *Server) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondError writes an error JSON response.
func (s *Server) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
	})
}
