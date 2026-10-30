package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrLoginFailed         = errors.New("authentication failed: invalid credentials or rejected by target")
	ErrRedirectLoopToLogin = errors.New("authentication redirected back to login page")
	ErrMissingSessionCookie= errors.New("required session cookie not present in authenticated state")
	ErrMalformedLoginForm  = errors.New("failed to parse login form from initial page")
	ErrVerificationFailed  = errors.New("authenticated follow-up verification request failed")
)

// SuccessCriteria defines how to verify that authentication succeeded.
type SuccessCriteria struct {
	ExpectedCookies     []string `json:"expected_cookies,omitempty"`
	ExpectedStatus      []int    `json:"expected_status,omitempty"`
	RedirectMatches     string   `json:"redirect_matches,omitempty"`
	RedirectNotMatches  string   `json:"redirect_not_matches,omitempty"`
	BodyMustContain     string   `json:"body_must_contain,omitempty"`
	BodyMustNotContain  string   `json:"body_must_not_contain,omitempty"`
}

// VerifyCriteria defines follow-up verification against a protected endpoint.
type VerifyCriteria struct {
	ExpectedStatus     []int  `json:"expected_status,omitempty"`
	BodyMustContain    string `json:"body_must_contain,omitempty"`
	BodyMustNotContain string `json:"body_must_not_contain,omitempty"`
}

// LoginMacroConfig declares the steps and criteria for a stateful login flow.
type LoginMacroConfig struct {
	Name            string            `json:"name"`
	TargetURL       string            `json:"target_url"`
	FormActionURL   string            `json:"form_action_url,omitempty"`
	Method          string            `json:"method,omitempty"`           // default POST
	ContentType     string            `json:"content_type,omitempty"`     // form-urlencoded (default) or json
	Credentials     map[string]string `json:"-"`                          // secret credentials NEVER serialized
	StaticFields    map[string]string `json:"static_fields,omitempty"`    // e.g. _csrf: ""
	ExtractFields   []string          `json:"extract_fields,omitempty"`   // form input fields to parse from HTML
	SuccessCriteria SuccessCriteria   `json:"success_criteria"`
	VerifyURL       string            `json:"verify_url,omitempty"`
	VerifyCriteria  VerifyCriteria    `json:"verify_criteria,omitempty"`
	Timeout         time.Duration     `json:"timeout,omitempty"`
	Transport       http.RoundTripper `json:"-"`
}

// MacroSession records the isolated outcome of a login macro execution.
type MacroSession struct {
	ID                  string            `json:"id"`
	Target              string            `json:"target"`
	Authenticated       bool              `json:"authenticated"`
	Status              AuthState         `json:"status"`
	CapturedCookieNames []string          `json:"captured_cookie_names"`
	HasBearerToken      bool              `json:"has_bearer_token"`
	AuthenticatedAt     time.Time         `json:"authenticated_at"`
	Duration            time.Duration     `json:"duration_ms"`
	FailureReason       string            `json:"failure_reason,omitempty"`
	Cookies             map[string]string `json:"-"` // secret values never in JSON
	BearerToken         string            `json:"-"` // secret token never in JSON
	Jar                 http.CookieJar    `json:"-"` // isolated per execution
	Client              *http.Client      `json:"-"` // isolated per execution
}

// LoginMacro manages stateful declarative authentication workflows.
type LoginMacro struct {
	cfg LoginMacroConfig
}

// NewLoginMacro creates a new login macro from configuration.
func NewLoginMacro(cfg LoginMacroConfig) *LoginMacro {
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.ContentType == "" {
		cfg.ContentType = "application/x-www-form-urlencoded"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &LoginMacro{cfg: cfg}
}

// Execute performs the multi-step authentication workflow:
// 1. GET login form -> parse initial cookies and hidden form fields.
// 2. Build and submit credentials (POST).
// 3. Inspect response & redirects -> capture authenticated session cookies.
// 4. Verify outcome against target-specific indicators.
// 5. Execute follow-up verification request if configured.
func (m *LoginMacro) Execute(ctx context.Context) (*MacroSession, error) {
	startTime := time.Now()
	timeout := m.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Enforce strict session isolation: fresh CookieJar per execution
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create isolated cookie jar: %w", err)
	}

	transport := m.cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	var lastRedirectURL string
	client := &http.Client{
		Jar:       jar,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			lastRedirectURL = req.URL.String()
			return nil
		},
	}

	targetParsed, err := url.Parse(m.cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", m.cfg.TargetURL, err)
	}

	session := &MacroSession{
		ID:              fmt.Sprintf("session-%d", time.Now().UnixNano()),
		Target:          m.cfg.TargetURL,
		Status:          AuthStateUnknown,
		Cookies:         make(map[string]string),
		Jar:             jar,
		Client:          client,
		AuthenticatedAt: time.Now(),
	}

	// STEP 1: GET login form
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.TargetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct GET login request: %w", err)
	}
	getReq.Header.Set("User-Agent", "Felix-Security-Scanner/3.0")

	getResp, err := client.Do(getReq)
	if err != nil {
		session.FailureReason = fmt.Sprintf("GET login form failed: %v", err)
		session.Duration = time.Since(startTime)
		return session, session.FailureReasonErr()
	}
	defer getResp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(getResp.Body, 1024*1024))
	if err != nil {
		session.FailureReason = fmt.Sprintf("failed to read login page body: %v", err)
		session.Duration = time.Since(startTime)
		return session, session.FailureReasonErr()
	}
	htmlContent := string(bodyBytes)

	// Extract form fields if configured
	extractedValues := make(map[string]string)
	if len(m.cfg.ExtractFields) > 0 {
		extractedValues = extractFormHiddenFields(htmlContent, m.cfg.ExtractFields)
	}

	// Resolve action URL
	actionURL := m.cfg.TargetURL
	if m.cfg.FormActionURL != "" {
		if strings.HasPrefix(m.cfg.FormActionURL, "http://") || strings.HasPrefix(m.cfg.FormActionURL, "https://") {
			actionURL = m.cfg.FormActionURL
		} else {
			relURL, pErr := url.Parse(m.cfg.FormActionURL)
			if pErr == nil {
				actionURL = targetParsed.ResolveReference(relURL).String()
			}
		}
	} else {
		// Attempt to extract action attribute from form in HTML
		if formAction := extractFormAction(htmlContent); formAction != "" {
			relURL, pErr := url.Parse(formAction)
			if pErr == nil {
				actionURL = targetParsed.ResolveReference(relURL).String()
			}
		}
	}

	// STEP 2: Build submission payload
	submissionData := make(map[string]string)
	for k, v := range m.cfg.StaticFields {
		submissionData[k] = v
	}
	for k, v := range extractedValues {
		submissionData[k] = v
	}
	for k, v := range m.cfg.Credentials {
		submissionData[k] = v
	}

	var reqBody io.Reader
	var contentType = m.cfg.ContentType

	if strings.Contains(strings.ToLower(contentType), "application/json") {
		jsonBytes, jErr := json.Marshal(submissionData)
		if jErr != nil {
			session.FailureReason = fmt.Sprintf("failed to marshal JSON credentials: %v", jErr)
			session.Duration = time.Since(startTime)
			return session, session.FailureReasonErr()
		}
		reqBody = bytes.NewReader(jsonBytes)
	} else {
		// Default form urlencoded
		contentType = "application/x-www-form-urlencoded"
		values := url.Values{}
		for k, v := range submissionData {
			values.Set(k, v)
		}
		reqBody = strings.NewReader(values.Encode())
	}

	// STEP 3: POST credentials
	postReq, err := http.NewRequestWithContext(ctx, m.cfg.Method, actionURL, reqBody)
	if err != nil {
		session.FailureReason = fmt.Sprintf("failed to construct POST login request: %v", err)
		session.Duration = time.Since(startTime)
		return session, session.FailureReasonErr()
	}
	postReq.Header.Set("Content-Type", contentType)
	postReq.Header.Set("User-Agent", "Felix-Security-Scanner/3.0")

	// Use a non-redirecting transport for the POST response to capture intermediate 302s
	// unless FollowRedirects is desired.
	postResp, err := client.Do(postReq)
	if err != nil {
		session.FailureReason = fmt.Sprintf("POST credentials failed: %v", err)
		session.Duration = time.Since(startTime)
		return session, session.FailureReasonErr()
	}
	defer postResp.Body.Close()

	postBodyBytes, _ := io.ReadAll(io.LimitReader(postResp.Body, 1024*1024))
	postBodyStr := string(postBodyBytes)

	// STEP 4: Capture session cookies from Jar for target URL
	jarCookies := jar.Cookies(targetParsed)
	capturedMap := make(map[string]string)
	var capturedNames []string
	for _, c := range jarCookies {
		capturedMap[c.Name] = c.Value
		capturedNames = append(capturedNames, c.Name)
	}
	session.Cookies = capturedMap
	session.CapturedCookieNames = capturedNames

	// STEP 5: Verify outcome against SuccessCriteria
	crit := m.cfg.SuccessCriteria

	// A: Check ExpectedStatus if set
	if len(crit.ExpectedStatus) > 0 {
		statusMatched := false
		for _, s := range crit.ExpectedStatus {
			if postResp.StatusCode == s {
				statusMatched = true
				break
			}
		}
		if !statusMatched {
			session.FailureReason = fmt.Sprintf("unexpected HTTP status %d, expected one of %v", postResp.StatusCode, crit.ExpectedStatus)
			session.Duration = time.Since(startTime)
			return session, ErrLoginFailed
		}
	}

	// B: Check redirect target if applicable
	effectiveRedirect := lastRedirectURL
	if effectiveRedirect == "" {
		effectiveRedirect = postResp.Header.Get("Location")
	}

	if crit.RedirectNotMatches != "" && effectiveRedirect != "" {
		if strings.Contains(effectiveRedirect, crit.RedirectNotMatches) {
			session.FailureReason = fmt.Sprintf("login redirected to failure path: %s", effectiveRedirect)
			session.Duration = time.Since(startTime)
			return session, ErrRedirectLoopToLogin
		}
	}

	if crit.RedirectMatches != "" {
		if !strings.Contains(effectiveRedirect, crit.RedirectMatches) {
			session.FailureReason = fmt.Sprintf("expected redirect to %q, got %q", crit.RedirectMatches, effectiveRedirect)
			session.Duration = time.Since(startTime)
			return session, ErrLoginFailed
		}
	}

	// C: Check body assertions
	if crit.BodyMustNotContain != "" && strings.Contains(postBodyStr, crit.BodyMustNotContain) {
		session.FailureReason = fmt.Sprintf("login response contains failure indicator: %q", crit.BodyMustNotContain)
		session.Duration = time.Since(startTime)
		return session, ErrLoginFailed
	}

	if crit.BodyMustContain != "" && !strings.Contains(postBodyStr, crit.BodyMustContain) {
		session.FailureReason = fmt.Sprintf("login response missing required indicator: %q", crit.BodyMustContain)
		session.Duration = time.Since(startTime)
		return session, ErrLoginFailed
	}

	// D: Check required session cookies
	if len(crit.ExpectedCookies) > 0 {
		for _, exp := range crit.ExpectedCookies {
			found := false
			for _, name := range capturedNames {
				if strings.EqualFold(name, exp) {
					found = true
					break
				}
			}
			if !found {
				session.FailureReason = fmt.Sprintf("missing required session cookie %q; captured: %v", exp, capturedNames)
				session.Duration = time.Since(startTime)
				return session, ErrMissingSessionCookie
			}
		}
	}

	// STEP 6: Execute follow-up verification request if configured
	if m.cfg.VerifyURL != "" {
		verifyReq, vErr := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.VerifyURL, nil)
		if vErr != nil {
			session.FailureReason = fmt.Sprintf("failed to construct verification request: %v", vErr)
			session.Duration = time.Since(startTime)
			return session, ErrVerificationFailed
		}
		verifyReq.Header.Set("User-Agent", "Felix-Security-Scanner/3.0")

		verifyResp, vErr := client.Do(verifyReq)
		if vErr != nil {
			session.FailureReason = fmt.Sprintf("verification request failed: %v", vErr)
			session.Duration = time.Since(startTime)
			return session, ErrVerificationFailed
		}
		defer verifyResp.Body.Close()

		vBodyBytes, _ := io.ReadAll(io.LimitReader(verifyResp.Body, 1024*1024))
		vBodyStr := string(vBodyBytes)

		vc := m.cfg.VerifyCriteria
		if len(vc.ExpectedStatus) > 0 {
			matched := false
			for _, s := range vc.ExpectedStatus {
				if verifyResp.StatusCode == s {
					matched = true
					break
				}
			}
			if !matched {
				session.FailureReason = fmt.Sprintf("verification endpoint returned status %d, expected %v", verifyResp.StatusCode, vc.ExpectedStatus)
				session.Duration = time.Since(startTime)
				return session, ErrVerificationFailed
			}
		}

		if vc.BodyMustContain != "" && !strings.Contains(vBodyStr, vc.BodyMustContain) {
			session.FailureReason = fmt.Sprintf("verification endpoint missing indicator: %q", vc.BodyMustContain)
			session.Duration = time.Since(startTime)
			return session, ErrVerificationFailed
		}

		if vc.BodyMustNotContain != "" && strings.Contains(vBodyStr, vc.BodyMustNotContain) {
			session.FailureReason = fmt.Sprintf("verification endpoint contains forbidden indicator: %q", vc.BodyMustNotContain)
			session.Duration = time.Since(startTime)
			return session, ErrVerificationFailed
		}
	}

	// Success confirmed
	session.Authenticated = true
	session.Status = AuthStateConfirmed
	session.Duration = time.Since(startTime)
	return session, nil
}

func (s *MacroSession) FailureReasonErr() error {
	if s.FailureReason != "" {
		return errors.New(s.FailureReason)
	}
	return ErrLoginFailed
}

// extractFormHiddenFields extracts input values for specified field names from an HTML document.
func extractFormHiddenFields(html string, fieldNames []string) map[string]string {
	results := make(map[string]string)
	wanted := make(map[string]struct{})
	for _, fn := range fieldNames {
		wanted[strings.ToLower(fn)] = struct{}{}
	}

	// Regex to match <input ...> tags
	inputRe := regexp.MustCompile(`(?i)<input\s+([^>]+)>`)
	nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	valueRe := regexp.MustCompile(`(?i)value=["']([^"']*)["']`)

	matches := inputRe.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		attrs := m[1]
		nameMatch := nameRe.FindStringSubmatch(attrs)
		if len(nameMatch) < 2 {
			continue
		}
		name := nameMatch[1]
		if _, ok := wanted[strings.ToLower(name)]; ok {
			val := ""
			valMatch := valueRe.FindStringSubmatch(attrs)
			if len(valMatch) >= 2 {
				val = valMatch[1]
			}
			results[name] = val
		}
	}
	return results
}

// extractFormAction extracts the action attribute from the first <form> tag.
func extractFormAction(html string) string {
	formRe := regexp.MustCompile(`(?i)<form\s+[^>]*action=["']([^"']+)["'][^>]*>`)
	m := formRe.FindStringSubmatch(html)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}
