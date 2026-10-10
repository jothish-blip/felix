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
	"strings"
	"time"

	"felix/pkg/assessment"
)

// Config holds runtime parameters for the Felix Operator HTTP server.
type Config struct {
	ListenHost string
	ListenPort int
	OperatorID string
	Token      string
	Store      assessment.Store
	JobManager *assessment.JobManager
	Version    string
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
			ListenHost: host,
			ListenPort: port,
			OperatorID: opID,
			Token:      token,
			Store:      cfg.Store,
			JobManager: jm,
			Version:    ver,
		},
		store:      cfg.Store,
		jobManager: jm,
		mux:        http.NewServeMux(),
		token:      token,
	}

	s.registerRoutes()
	return s, nil
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
		// Non-API paths (static assets) and health check are public
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Check header X-Felix-Operator-Token
		token := r.Header.Get("X-Felix-Operator-Token")

		// Or Authorization: Bearer <token>
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// Or query param token (convenient for browser file downloads or embeds)
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
			s.respondError(w, http.StatusUnauthorized, "unauthorized: missing or invalid operator token")
			return
		}

		next.ServeHTTP(w, r)
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
