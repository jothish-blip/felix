package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

var (
	ErrNoCSRFTokenFound       = errors.New("no anti-CSRF token found in response")
	ErrCSRFTokenMissing       = errors.New("required anti-CSRF token not present for session")
	ErrCSRFRejection          = errors.New("request rejected due to invalid or stale anti-CSRF token")
	ErrNonReplayableBody      = errors.New("cannot retry CSRF-rejected request: request body is not replayable")
	ErrStaleTokenResponse     = errors.New("ignored stale token response from earlier sequence")
	ErrSessionIDRequired      = errors.New("session ID is required for CSRF token tracking")
)

// DefaultTokenFieldNames lists standard parameter and hidden field names for anti-CSRF tokens.
var DefaultTokenFieldNames = []string{
	"user_token",                 // DVWA
	"_csrf",                      // Spring Security, csurf
	"csrf_token",                 // Flask-WTF, OWASP
	"csrftoken",                  // Django
	"authenticity_token",         // Ruby on Rails
	"__RequestVerificationToken", // ASP.NET
	"anti_forgery_token",
	"csrf",
	"xsrf_token",
	"xsrf-token",
}

// DefaultHeaderNames lists standard HTTP header names for anti-CSRF tokens.
var DefaultHeaderNames = []string{
	"X-CSRF-Token",
	"X-CSRF-Header",
	"X-XSRF-Token",
	"X-CSRF-PARAM",
	"CSRF-Token",
	"X-Requested-With",
}

// CSRFConfig defines configuration for anti-CSRF synchronization.
type CSRFConfig struct {
	Name              string
	TokenFieldNames   []string // Parameter/form field names to look for
	HeaderNames       []string // HTTP response/request header names
	TokenFetchURL     string   // Optional URL to GET for fresh tokens
	InjectionHeader   string   // If set, inject token in this header (e.g. "X-CSRF-Token")
	InjectionParam    string   // Parameter name to inject into form/JSON (default: first from TokenFieldNames)
	MutatingMethods   []string // HTTP methods requiring CSRF protection (default: POST, PUT, PATCH, DELETE)
	AutoExtract       bool     // Automatically extract tokens from responses
	SingleUseTokens   bool     // If true, serialize mutating requests per session to handle rotating nonces
	IsCSRFFailureFunc func(resp *http.Response, body []byte) bool
}

// CSRFTokenState represents the sanitized internal state of an extracted token.
type CSRFTokenState struct {
	TokenName   string    `json:"token_name"`
	Value       string    `json:"-"` // Never serialized to JSON or logs
	SessionID   string    `json:"session_id"`
	ExtractedAt time.Time `json:"extracted_at"`
	SourceURL   string    `json:"source_url,omitempty"`
	SequenceID  int64     `json:"sequence_id"`
}

// SessionTokenState manages thread-safe token storage and mutation serialization for a specific session.
type SessionTokenState struct {
	sessionID   string
	mu          sync.RWMutex
	mutationMu  sync.Mutex // Serializes token-dependent mutations to prevent single-use token races
	activeToken string
	tokenName   string
	lastSeqID   int64
	seqCounter  int64
	extractedAt time.Time
}

// CSRFMetrics tracks operational counters for CSRF synchronization.
type CSRFMetrics struct {
	TokensExtracted      int64   `json:"tokens_extracted"`
	TokensInjected       int64   `json:"tokens_injected"`
	TokensRotated        int64   `json:"tokens_rotated"`
	ValidRequests        int64   `json:"valid_requests"`
	StaleTokenRejections int64   `json:"stale_token_rejections"`
	False403Count        int64   `json:"false_403_count"`
	SyncSuccessRate      float64 `json:"sync_success_rate"`
}

// CSRFSynchronizer manages autonomous extraction, per-session synchronization,
// and safe injection of anti-CSRF tokens across concurrent operations.
type CSRFSynchronizer struct {
	cfg      CSRFConfig
	mu       sync.RWMutex
	sessions map[string]*SessionTokenState

	// Atomic counters
	tokensExtracted      int64
	tokensInjected       int64
	tokensRotated        int64
	validRequests        int64
	staleTokenRejections int64
	false403Count        int64
}

// NewCSRFSynchronizer creates a new synchronizer instance from configuration.
func NewCSRFSynchronizer(cfg CSRFConfig) *CSRFSynchronizer {
	if len(cfg.TokenFieldNames) == 0 {
		cfg.TokenFieldNames = DefaultTokenFieldNames
	}
	if len(cfg.HeaderNames) == 0 {
		cfg.HeaderNames = DefaultHeaderNames
	}
	if len(cfg.MutatingMethods) == 0 {
		cfg.MutatingMethods = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	}
	if cfg.InjectionParam == "" && len(cfg.TokenFieldNames) > 0 {
		cfg.InjectionParam = cfg.TokenFieldNames[0]
	}

	return &CSRFSynchronizer{
		cfg:      cfg,
		sessions: make(map[string]*SessionTokenState),
	}
}

// getOrCreateSessionState retrieves or initializes state for a session.
func (s *CSRFSynchronizer) getOrCreateSessionState(sessionID string) *SessionTokenState {
	if sessionID == "" {
		sessionID = "default"
	}

	s.mu.RLock()
	st, exists := s.sessions[sessionID]
	s.mu.RUnlock()
	if exists {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if st, exists = s.sessions[sessionID]; exists {
		return st
	}

	st = &SessionTokenState{
		sessionID: sessionID,
	}
	s.sessions[sessionID] = st
	return st
}

// NextSequence increments and returns the next monotonic sequence ID for this session.
func (s *CSRFSynchronizer) NextSequence(sessionID string) int64 {
	st := s.getOrCreateSessionState(sessionID)
	return atomic.AddInt64(&st.seqCounter, 1)
}

// ExtractToken parses an HTTP response and extracts any anti-CSRF token present.
// It checks response headers, HTML body (<input> and <meta>), and JSON payloads.
// Extracted tokens are checked against seqID to ensure out-of-order network responses
// do not overwrite newer tokens.
func (s *CSRFSynchronizer) ExtractToken(resp *http.Response, body []byte, sessionID string, seqID int64) (string, error) {
	if resp == nil {
		return "", errors.New("cannot extract token from nil response")
	}
	if sessionID == "" {
		return "", ErrSessionIDRequired
	}

	var foundName, foundVal string

	// 1. Check response headers
	for _, h := range s.cfg.HeaderNames {
		if val := resp.Header.Get(h); val != "" {
			foundName = h
			foundVal = val
			break
		}
		for k, v := range resp.Header {
			if strings.EqualFold(k, h) && len(v) > 0 && v[0] != "" {
				foundName = k
				foundVal = v[0]
				break
			}
		}
		if foundVal != "" {
			break
		}
	}

	// 2. Check HTML body if not found in headers
	if foundVal == "" && len(body) > 0 {
		ct := resp.Header.Get("Content-Type")
		if ct == "" || strings.Contains(strings.ToLower(ct), "text/html") || strings.Contains(strings.ToLower(ct), "text/plain") {
			name, val := extractFromHTML(body, s.cfg.TokenFieldNames)
			if val != "" {
				foundName = name
				foundVal = val
			}
		}
	}

	// 3. Check JSON body if configured and content-type matches
	if foundVal == "" && len(body) > 0 {
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(strings.ToLower(ct), "application/json") {
			name, val := extractFromJSON(body, s.cfg.TokenFieldNames)
			if val != "" {
				foundName = name
				foundVal = val
			}
		}
	}

	if foundVal == "" {
		return "", ErrNoCSRFTokenFound
	}

	// Atomically store token if not superseded by a newer sequence
	st := s.getOrCreateSessionState(sessionID)
	st.mu.Lock()
	defer st.mu.Unlock()

	if seqID > 0 && seqID < st.lastSeqID {
		// Out-of-order response: an earlier request completed after a newer one
		return "", ErrStaleTokenResponse
	}

	isRotation := st.activeToken != "" && st.activeToken != foundVal
	st.activeToken = foundVal
	st.tokenName = foundName
	st.extractedAt = time.Now()
	if seqID > st.lastSeqID {
		st.lastSeqID = seqID
	}

	atomic.AddInt64(&s.tokensExtracted, 1)
	if isRotation {
		atomic.AddInt64(&s.tokensRotated, 1)
	}

	return foundVal, nil
}

// GetToken retrieves the active anti-CSRF token for the specified session.
func (s *CSRFSynchronizer) GetToken(sessionID string) (string, string, bool) {
	st := s.getOrCreateSessionState(sessionID)
	st.mu.RLock()
	defer st.mu.RUnlock()

	if st.activeToken == "" {
		return "", "", false
	}
	return st.tokenName, st.activeToken, true
}

// SetToken manually updates the active anti-CSRF token for a session.
func (s *CSRFSynchronizer) SetToken(sessionID, tokenName, tokenVal string) {
	st := s.getOrCreateSessionState(sessionID)
	st.mu.Lock()
	defer st.mu.Unlock()

	isRotation := st.activeToken != "" && st.activeToken != tokenVal
	st.activeToken = tokenVal
	st.tokenName = tokenName
	st.extractedAt = time.Now()

	atomic.AddInt64(&s.tokensExtracted, 1)
	if isRotation {
		atomic.AddInt64(&s.tokensRotated, 1)
	}
}

// InvalidateToken clears the active token for a session.
func (s *CSRFSynchronizer) InvalidateToken(sessionID string) {
	st := s.getOrCreateSessionState(sessionID)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.activeToken = ""
}

// IsMutatingMethod checks whether an HTTP method is configured as state-changing.
func (s *CSRFSynchronizer) IsMutatingMethod(method string) bool {
	upper := strings.ToUpper(method)
	for _, m := range s.cfg.MutatingMethods {
		if strings.ToUpper(m) == upper {
			return true
		}
	}
	return false
}

// InjectToken injects the active token for the session into a mutating request.
// For GET/HEAD/OPTIONS, InjectToken is a safe no-op.
// For mutating methods, it injects into headers, urlencoded forms, or JSON bodies.
func (s *CSRFSynchronizer) InjectToken(req *http.Request, sessionID string) error {
	if req == nil {
		return errors.New("cannot inject token into nil request")
	}

	if !s.IsMutatingMethod(req.Method) {
		return nil // Non-mutating requests are never modified
	}

	_, token, exists := s.GetToken(sessionID)
	if !exists || token == "" {
		return ErrCSRFTokenMissing
	}

	// 1. Header injection if configured
	if s.cfg.InjectionHeader != "" {
		req.Header.Set(s.cfg.InjectionHeader, token)
	}

	// 2. Body injection based on Content-Type
	paramName := s.cfg.InjectionParam
	if paramName == "" && len(s.cfg.TokenFieldNames) > 0 {
		paramName = s.cfg.TokenFieldNames[0]
	}

	ct := req.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)

	if strings.EqualFold(mediaType, "application/x-www-form-urlencoded") || ct == "" {
		var bodyBytes []byte
		if req.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return fmt.Errorf("failed to read form body: %w", err)
			}
		}

		values, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			values = url.Values{}
		}
		values.Set(paramName, token)
		encoded := values.Encode()

		req.Body = io.NopCloser(strings.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(encoded)), nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if strings.EqualFold(mediaType, "application/json") {
		var bodyBytes []byte
		if req.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return fmt.Errorf("failed to read JSON body: %w", err)
			}
		}

		jsonMap := make(map[string]any)
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &jsonMap)
		}
		jsonMap[paramName] = token

		encoded, err := json.Marshal(jsonMap)
		if err != nil {
			return fmt.Errorf("failed to marshal updated JSON: %w", err)
		}

		req.Body = io.NopCloser(bytes.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(encoded)), nil
		}
	} else if strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
		// For multipart requests, inject header fallback
		if s.cfg.InjectionHeader == "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}

	atomic.AddInt64(&s.tokensInjected, 1)
	return nil
}

// FetchInitialToken fetches a fresh token using the configured TokenFetchURL.
func (s *CSRFSynchronizer) FetchInitialToken(ctx context.Context, client *http.Client, sessionID string) (string, error) {
	if s.cfg.TokenFetchURL == "" {
		return "", errors.New("no TokenFetchURL configured")
	}
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.TokenFetchURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to construct token fetch request: %w", err)
	}
	req.Header.Set("User-Agent", "Felix-Security-Scanner/3.0")

	seqID := s.NextSequence(sessionID)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token fetch request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return s.ExtractToken(resp, bodyBytes, sessionID, seqID)
}

// IsCSRFRejection determines if an HTTP response represents a genuine anti-CSRF rejection.
// It explicitly distinguishes anti-CSRF rejection from ordinary application authorization
// or permission denial (e.g. BOLA/IDOR HTTP 403), avoiding false token refreshes.
func (s *CSRFSynchronizer) IsCSRFRejection(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}

	if s.cfg.IsCSRFFailureFunc != nil {
		return s.cfg.IsCSRFFailureFunc(resp, body)
	}

	// Must be HTTP 403 or 400
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
		return false
	}

	// 1. Explicit CSRF rejection headers
	if resp.Header.Get("X-CSRF-Error") != "" || resp.Header.Get("X-CSRF-Rejected") == "true" {
		return true
	}

	// 2. Explicit body indicators matching anti-CSRF verification failures
	bodyLower := strings.ToLower(string(body))
	csrfIndicators := []string{
		"csrf token is incorrect",     // DVWA
		"csrf token mismatch",         // Laravel
		"invalid csrf token",          // Express csurf
		"csrf verification failed",    // Django
		"anti-forgery token",
		"xsrf token missing",
		"invalid authenticity token",  // Rails
		"token has expired",
		"bad csrf token",
	}

	for _, ind := range csrfIndicators {
		if strings.Contains(bodyLower, ind) {
			return true
		}
	}

	return false
}

// ExecuteMutating executes a state-changing request with synchronized anti-CSRF protection.
// If SingleUseTokens is configured, it serializes mutating requests on the session's
// mutation lock to eliminate race conditions on single-use nonces.
// If the initial request fails with a verified CSRF rejection, it fetches a fresh token,
// rewinds the body via req.GetBody, and retries the request exactly once.
func (s *CSRFSynchronizer) ExecuteMutating(ctx context.Context, client *http.Client, req *http.Request, sessionID string) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("cannot execute nil request")
	}
	if client == nil {
		client = http.DefaultClient
	}
	if sessionID == "" {
		sessionID = "default"
	}

	isMutating := s.IsMutatingMethod(req.Method)
	canReplay := req.GetBody != nil
	st := s.getOrCreateSessionState(sessionID)

	// If single-use rotating tokens are used, serialize mutations per session
	if isMutating && s.cfg.SingleUseTokens {
		st.mutationMu.Lock()
		defer st.mutationMu.Unlock()
	}

	// Ensure token is present before executing
	if isMutating {
		_, _, exists := s.GetToken(sessionID)
		if !exists && s.cfg.TokenFetchURL != "" {
			_, _ = s.FetchInitialToken(ctx, client, sessionID)
		}

		if err := s.InjectToken(req, sessionID); err != nil {
			return nil, fmt.Errorf("failed to inject anti-CSRF token: %w", err)
		}
	}

	seqID := s.NextSequence(sessionID)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Read bounded body for inspection
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	_ = resp.Body.Close()

	// Restore response body for caller
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Check for positive CSRF rejection
	if isMutating && s.IsCSRFRejection(resp, bodyBytes) {
		atomic.AddInt64(&s.staleTokenRejections, 1)

		// Only retry if request body was originally safely replayable
		if !canReplay {
			return resp, ErrNonReplayableBody
		}

		// Attempt fresh token retrieval
		freshToken := ""
		if s.cfg.TokenFetchURL != "" {
			freshToken, _ = s.FetchInitialToken(ctx, client, sessionID)
		} else {
			// Extract from response if available
			freshToken, _ = s.ExtractToken(resp, bodyBytes, sessionID, seqID)
		}

		if freshToken != "" {
			// Rewind request body and re-inject fresh token
			newBody, bErr := req.GetBody()
			if bErr == nil {
				req.Body = newBody
				if injErr := s.InjectToken(req, sessionID); injErr == nil {
					retrySeq := s.NextSequence(sessionID)
					retryResp, rErr := client.Do(req)
					if rErr == nil {
						rBody, _ := io.ReadAll(io.LimitReader(retryResp.Body, 1024*1024))
						_ = retryResp.Body.Close()
						retryResp.Body = io.NopCloser(bytes.NewReader(rBody))

						if !s.IsCSRFRejection(retryResp, rBody) {
							atomic.AddInt64(&s.validRequests, 1)
							if s.cfg.AutoExtract {
								_, _ = s.ExtractToken(retryResp, rBody, sessionID, retrySeq)
							}
							return retryResp, nil
						}
						// If retry still rejected, count as failure
						atomic.AddInt64(&s.false403Count, 1)
						return retryResp, ErrCSRFRejection
					}
				}
			}
		}

		return resp, ErrCSRFRejection
	}

	// Valid response
	if isMutating {
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusCreated {
			atomic.AddInt64(&s.validRequests, 1)
		} else if resp.StatusCode == http.StatusForbidden {
			// Ordinary non-CSRF 403 (authorization denied / BOLA probe)
			// Do NOT count as false 403 or CSRF rejection
		}
	}

	// Auto-extract rotated token from response if present
	if s.cfg.AutoExtract {
		_, _ = s.ExtractToken(resp, bodyBytes, sessionID, seqID)
	}

	return resp, nil
}

// Metrics returns snapshot copy of operational counters and calculates success rate.
func (s *CSRFSynchronizer) Metrics() CSRFMetrics {
	extracted := atomic.LoadInt64(&s.tokensExtracted)
	injected := atomic.LoadInt64(&s.tokensInjected)
	rotated := atomic.LoadInt64(&s.tokensRotated)
	valid := atomic.LoadInt64(&s.validRequests)
	stale := atomic.LoadInt64(&s.staleTokenRejections)
	false403 := atomic.LoadInt64(&s.false403Count)

	rate := 100.0
	totalMutations := valid + false403
	if totalMutations > 0 {
		rate = (float64(valid) / float64(totalMutations)) * 100.0
	}

	return CSRFMetrics{
		TokensExtracted:      extracted,
		TokensInjected:       injected,
		TokensRotated:        rotated,
		ValidRequests:        valid,
		StaleTokenRejections: stale,
		False403Count:        false403,
		SyncSuccessRate:      rate,
	}
}

// extractFromHTML traverses the parsed DOM and extracts hidden anti-CSRF fields or meta tags.
func extractFromHTML(htmlContent []byte, tokenNames []string) (string, string) {
	doc, err := html.Parse(bytes.NewReader(htmlContent))
	if err != nil {
		return "", ""
	}

	wanted := make(map[string]struct{})
	for _, tn := range tokenNames {
		wanted[strings.ToLower(tn)] = struct{}{}
	}

	var foundName, foundVal string
	var traverse func(*html.Node) bool
	traverse = func(n *html.Node) bool {
		if n.Type == html.ElementNode {
			if strings.EqualFold(n.Data, "input") {
				var isHidden bool
				var nameVal, valVal string
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "type") && strings.EqualFold(attr.Val, "hidden") {
						isHidden = true
					}
					if strings.EqualFold(attr.Key, "name") {
						nameVal = attr.Val
					}
					if strings.EqualFold(attr.Key, "value") {
						valVal = attr.Val
					}
				}
				if isHidden && nameVal != "" && valVal != "" {
					if _, ok := wanted[strings.ToLower(nameVal)]; ok {
						foundName = nameVal
						foundVal = valVal
						return true
					}
				}
			} else if strings.EqualFold(n.Data, "meta") {
				var nameVal, contentVal string
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "name") {
						nameVal = attr.Val
					}
					if strings.EqualFold(attr.Key, "content") {
						contentVal = attr.Val
					}
				}
				if nameVal != "" && contentVal != "" {
					if _, ok := wanted[strings.ToLower(nameVal)]; ok {
						foundName = nameVal
						foundVal = contentVal
						return true
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if traverse(c) {
				return true
			}
		}
		return false
	}

	traverse(doc)
	return foundName, foundVal
}

// extractFromJSON decodes a JSON object and extracts matching token fields.
func extractFromJSON(jsonContent []byte, tokenNames []string) (string, string) {
	var m map[string]any
	if err := json.Unmarshal(jsonContent, &m); err != nil {
		return "", ""
	}

	wanted := make(map[string]struct{})
	for _, tn := range tokenNames {
		wanted[strings.ToLower(tn)] = struct{}{}
	}

	for k, v := range m {
		if _, ok := wanted[strings.ToLower(k)]; ok {
			if strVal, ok := v.(string); ok && strVal != "" {
				return k, strVal
			}
		}
	}
	return "", ""
}
