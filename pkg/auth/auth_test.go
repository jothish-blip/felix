package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/crawler"
	"felix/pkg/discovery"
)

func TestClassifier_RoutesAndTaxonomy(t *testing.T) {
	classifier := NewClassifier()

	cases := []struct {
		path        string
		expectedCat AuthCategory
		expectedSub AuthSubtype
		expectMatch bool
	}{
		{"/login", CategoryLogin, SubtypePassword, true},
		{"/auth/signin", CategoryLogin, SubtypePassword, true},
		{"/signup", CategoryRegistration, SubtypePassword, true},
		{"/account/register", CategoryRegistration, SubtypePassword, true},
		{"/forgot-password", CategoryPasswordReset, SubtypePassword, true},
		{"/auth/reset-password", CategoryPasswordReset, SubtypePassword, true},
		{"/mfa/verify", CategoryMFA, SubtypeTOTP, true},
		{"/auth/webauthn/challenge", CategoryMFA, SubtypeWebAuthnPasskey, true},
		{"/logout", CategorySession, SubtypeLogout, true},
		{"/auth/session", CategorySession, SubtypeSessionStatus, true},
		{"/token/refresh", CategorySession, SubtypeTokenRefresh, true},
		{"/oauth/authorize", CategoryOAuthSSO, SubtypeOAuthOIDC, true},
		{"/saml/login", CategoryOAuthSSO, SubtypeSAML, true},
		{"/magic-link/send", CategoryAlternative, SubtypeMagicLink, true},
		{"/about-us", "", "", false},
		{"/blog/post-1", "", "", false},
	}

	for _, tc := range cases {
		cat, sub, matched, _ := classifier.ClassifyRoute(tc.path)
		if matched != tc.expectMatch {
			t.Errorf("path %q: expected match=%t, got %t", tc.path, tc.expectMatch, matched)
		}
		if matched {
			if cat != tc.expectedCat {
				t.Errorf("path %q: expected category %s, got %s", tc.path, tc.expectedCat, cat)
			}
			if sub != tc.expectedSub {
				t.Errorf("path %q: expected subtype %s, got %s", tc.path, tc.expectedSub, sub)
			}
		}
	}
}

func TestClassifier_ParameterHeuristics(t *testing.T) {
	classifier := NewClassifier()

	// NexSpace case: route is /api/broadcast with GoTrue auth parameters
	params := []string{"email", "password", "code_verifier", "code_challenge", "webauthn"}
	cat, sub, matched, _ := classifier.ClassifyFromParameters("/api/broadcast", params)

	if !matched {
		t.Fatalf("expected /api/broadcast with auth parameters to match auth classification")
	}
	// Has password and email -> classified as Login or MFA
	if cat != CategoryLogin && cat != CategoryMFA {
		t.Errorf("expected CategoryLogin or CategoryMFA, got: %s (sub: %s)", cat, sub)
	}

	// Password reset params
	resetParams := []string{"password", "recovery_token"}
	rCat, rSub, rMatched, _ := classifier.ClassifyFromParameters("/api/v1/update", resetParams)
	if !rMatched || rCat != CategoryPasswordReset || rSub != SubtypePassword {
		t.Errorf("expected PasswordReset, got: matched=%t, cat=%s, sub=%s", rMatched, rCat, rSub)
	}
}

func TestClassifier_SDKSignatures(t *testing.T) {
	classifier := NewClassifier()

	supabaseJS := `import { createClient } from '@supabase/supabase-js'; const x = gotrue_meta_security;`
	surfaces := classifier.ClassifyScriptSDK(supabaseJS, "bundle.js", "asm-1", "exec-1", "tgt-1", "app-1")

	foundSupabase := false
	for _, s := range surfaces {
		if s.Identifier == "Supabase GoTrue Auth" {
			foundSupabase = true
		}
	}
	if !foundSupabase {
		t.Errorf("expected Supabase GoTrue Auth SDK surface to be detected")
	}
}

func TestCookies_AnalysisAndSecurityFlags(t *testing.T) {
	headers := http.Header{}
	// Insecure session cookie (missing HttpOnly, missing Secure, unset SameSite)
	headers.Add("Set-Cookie", "session_id=SECRET12345; Path=/")
	// Secure preference cookie
	headers.Add("Set-Cookie", "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax")

	cookies := ParseAndAnalyzeCookies(headers, "https://example.com", "asm-1", "exec-1", "tgt-1")

	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies parsed, got %d", len(cookies))
	}

	var sessionCookie, themeCookie *CookieMetadata
	for i := range cookies {
		if cookies[i].Name == "session_id" {
			sessionCookie = &cookies[i]
		}
		if cookies[i].Name == "theme" {
			themeCookie = &cookies[i]
		}
	}

	if sessionCookie == nil || !sessionCookie.IsSession {
		t.Errorf("expected session_id to be classified as session cookie")
	}
	if !sessionCookie.HasSecurityIssue {
		t.Errorf("expected session_id to have security defects (missing HttpOnly and Secure)")
	}
	if len(sessionCookie.SecurityDefects) < 2 {
		t.Errorf("expected at least 2 defects for session_id, got: %v", sessionCookie.SecurityDefects)
	}

	if themeCookie == nil || themeCookie.IsSession {
		t.Errorf("theme cookie should not be classified as session")
	}
	if themeCookie.HasSecurityIssue {
		t.Errorf("theme cookie should not be flagged as insecure")
	}
}

func TestTokens_JWTAndPKCEAnalysis(t *testing.T) {
	// Sample HS256 JWT (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doz...)
	jsContent := `
		const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
		const pkce = { code_challenge: "abc", code_challenge_method: "plain" };
	`

	tokens := ExtractAndAnalyzeTokens(jsContent, "app.js", "asm-1", "exec-1", "tgt-1")

	foundJWT := false
	foundPKCE := false

	for _, tok := range tokens {
		if tok.TokenType == "JWT" {
			foundJWT = true
			if tok.Algorithm != "HS256" {
				t.Errorf("expected JWT algorithm HS256, got: %s", tok.Algorithm)
			}
		}
		if tok.TokenType == "PKCE" {
			foundPKCE = true
			if tok.Algorithm != "PLAIN" {
				t.Errorf("expected PKCE algorithm PLAIN, got: %s", tok.Algorithm)
			}
		}
	}

	if !foundJWT {
		t.Errorf("expected JWT token artifact to be extracted")
	}
	if !foundPKCE {
		t.Errorf("expected PKCE token artifact to be extracted")
	}
}

func TestProtectedEndpoint_Reasoning(t *testing.T) {
	classifier := NewProtectedEndpointClassifier()

	// 401 Unauthorized
	p1 := classifier.EvaluateEndpointProtection("/api/profile", "GET", 401, "Bearer realm=access", "", []string{})
	if p1.ProtectionStatus != "CONFIRMED_PROTECTED" || p1.Confidence != ConfidenceHigh {
		t.Errorf("expected CONFIRMED_PROTECTED with High confidence, got: %s (%s)", p1.ProtectionStatus, p1.Confidence)
	}

	// 403 Forbidden
	p2 := classifier.EvaluateEndpointProtection("/api/admin", "GET", 403, "", "", []string{})
	if p2.ProtectionStatus != "INFERRED_PROTECTED" || p2.Confidence != ConfidenceMedium {
		t.Errorf("expected INFERRED_PROTECTED with Medium confidence, got: %s (%s)", p2.ProtectionStatus, p2.Confidence)
	}

	// 302 Redirect to /login
	p3 := classifier.EvaluateEndpointProtection("/dashboard", "GET", 302, "", "/auth/login", []string{})
	if p3.ProtectionStatus != "INFERRED_PROTECTED" {
		t.Errorf("expected INFERRED_PROTECTED, got: %s", p3.ProtectionStatus)
	}

	// 302 Redirect to non-login (e.g. root)
	p3b := classifier.EvaluateEndpointProtection("/old-page", "GET", 302, "", "/home", []string{})
	if p3b.ProtectionStatus != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for general redirect, got: %s", p3b.ProtectionStatus)
	}

	// 200 OK on anonymous route
	p4 := classifier.EvaluateEndpointProtection("/public", "GET", 200, "", "", []string{})
	if p4.ProtectionStatus != "ANONYMOUS_ACCESSIBLE" {
		t.Errorf("expected ANONYMOUS_ACCESSIBLE, got: %s", p4.ProtectionStatus)
	}

	// 404 Not Found
	p5 := classifier.EvaluateEndpointProtection("/missing", "GET", 404, "", "", []string{})
	if p5.ProtectionStatus != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for 404, got: %s", p5.ProtectionStatus)
	}
}

func TestEngine_EndToEndAndSafetyGuarantees(t *testing.T) {
	var formSubmissionCount int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt64(&formSubmissionCount, 1)
		}
		w.Header().Set("Set-Cookie", "sid=secret_sess_val; Path=/; HttpOnly")
		w.Header().Set("WWW-Authenticate", "Bearer realm=example")
		_, _ = w.Write([]byte(`<html><body><form action="/auth/login" method="POST"><input type="password" name="password"/></form></body></html>`))
	}))
	defer ts.Close()

	engine := NewEngine()

	inv := &discovery.Inventory{
		Assets: []discovery.Asset{
			{
				ID:          "ep-1",
				Type:        discovery.AssetTypeEndpoint,
				CanonicalID: "POST /auth/login",
				Metadata: map[string]any{
					"path":   "/auth/login",
					"method": "POST",
				},
				Evidence: map[string]any{
					"status_code": 401,
				},
			},
		},
	}

	crawledAssets := []crawler.Asset{
		{
			URL:     ts.URL + "/main.js",
			Content: []byte(`const x = "code_challenge_method=plain";`),
		},
	}

	headers := http.Header{}
	headers.Add("Set-Cookie", "auth_token=raw_secret_value; Path=/; Secure") // Missing HttpOnly

	authInv, findings := engine.AnalyzeAuthentication(inv, crawledAssets, headers, ts.URL, "asm-test", "exec-test", "tgt-test")

	// Safety Check: Zero form submissions
	if atomic.LoadInt64(&formSubmissionCount) != 0 {
		t.Errorf("SAFETY VIOLATION: Engine made %d form submissions; expected 0", formSubmissionCount)
	}

	// Surfaces should include /auth/login
	if len(authInv.Surfaces) == 0 {
		t.Errorf("expected at least 1 auth surface, got 0")
	}

	// Cookies should include auth_token
	if len(authInv.Cookies) == 0 {
		t.Errorf("expected cookie to be parsed")
	} else {
		c := authInv.Cookies[0]
		if !c.IsSession {
			t.Errorf("auth_token should be classified as session cookie")
		}
		if !c.HasSecurityIssue {
			t.Errorf("auth_token missing HttpOnly should be flagged as security issue")
		}
	}

	// Tokens should detect PKCE plain
	foundPlainPKCE := false
	for _, tok := range authInv.Tokens {
		if tok.TokenType == "PKCE" && tok.Algorithm == "PLAIN" {
			foundPlainPKCE = true
		}
	}
	if !foundPlainPKCE {
		t.Errorf("expected PKCE plain to be extracted")
	}

	// Findings should contain cookie issue and PKCE plain
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestAccuracy_JWTAlgorithmNoneAndRedaction(t *testing.T) {
	engine := NewEngine()

	// 1. Synthetic token with alg=none and synthetic claims containing secrets
	// Header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	// Payload: {"sub":"user123","secret":"STAGE31_TEST_PASSWORD_9F3A"} -> eyJzdWIiOiJ1c2VyMTIzIiwic2VjcmV0IjoiU1RBR0UzMV9URVNUX1BBU1NXT1JEXzlGM0EifQ
	unsignedJWT := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwic2VjcmV0IjoiU1RBR0UzMV9URVNUX1BBU1NXT1JEXzlGM0EifQ."

	// 2. Normal RS256 token
	// Header: {"alg":"RS256","typ":"JWT"} -> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
	normalJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// 3. String merely resembling token (not base64 JSON header)
	fakeJWT := "eyJ1234567890abc.eyJ1234567890def.xyz"

	// 4. Malformed token structure
	malformed := "not.a.token"

	content := unsignedJWT + "\n" + normalJWT + "\n" + fakeJWT + "\n" + malformed
	assets := []crawler.Asset{
		{
			URL:     "https://example.com/app.js?token=STAGE31_FAKE_API_SECRET_6D1A",
			Content: []byte(content),
		},
	}

	authInv, findings := engine.AnalyzeAuthentication(nil, assets, http.Header{}, "https://example.com", "asm-1", "exec-1", "tgt-1")

	// Verify JWT artifacts
	var noneTok, rs256Tok *TokenArtifact
	for i := range authInv.Tokens {
		if authInv.Tokens[i].TokenType == "JWT" {
			if authInv.Tokens[i].Algorithm == "none" {
				noneTok = &authInv.Tokens[i]
			} else if authInv.Tokens[i].Algorithm == "RS256" {
				rs256Tok = &authInv.Tokens[i]
			}
		}
	}

	if noneTok == nil {
		t.Fatalf("expected alg=none token artifact to be extracted")
	}
	if rs256Tok == nil {
		t.Fatalf("expected RS256 token artifact to be extracted")
	}

	// Verify unverified JWT finding accuracy
	foundNoneFinding := false
	for _, f := range findings {
		if f.Category == "Authentication / Token Security" {
			foundNoneFinding = true
			if f.Severity != "INFO" {
				t.Errorf("expected INFO severity for static unverified JWT finding, got %s", f.Severity)
			}
			if f.Verification.Status != "NOT_VERIFIED" {
				t.Errorf("expected NOT_VERIFIED status, got %s", f.Verification.Status)
			}
			if f.Score > 15 {
				t.Errorf("expected conservative score <= 15, got %d", f.Score)
			}
		}
	}
	if !foundNoneFinding {
		t.Errorf("expected unverified finding for alg=none token")
	}

	// Secret Redaction Checks: Secret from claims and secret from URL parameter must be absent
	for _, tok := range authInv.Tokens {
		if strings.Contains(tok.SourceAsset, "STAGE31_FAKE_API_SECRET_6D1A") {
			t.Errorf("LEAK: Secret parameter leaked in Token.SourceAsset: %s", tok.SourceAsset)
		}
		if strings.Contains(tok.EvidenceSummary, "STAGE31_TEST_PASSWORD_9F3A") {
			t.Errorf("LEAK: Secret claim leaked in Token.EvidenceSummary: %s", tok.EvidenceSummary)
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Endpoint, "STAGE31_FAKE_API_SECRET_6D1A") || strings.Contains(f.Target, "STAGE31_FAKE_API_SECRET_6D1A") {
			t.Errorf("LEAK: Secret parameter leaked in Finding target/endpoint")
		}
		if strings.Contains(f.Evidence, "STAGE31_TEST_PASSWORD_9F3A") || strings.Contains(f.Description, "STAGE31_TEST_PASSWORD_9F3A") {
			t.Errorf("LEAK: Secret claim leaked in Finding evidence/description")
		}
	}
}

func TestAccuracy_PKCEPlainFinding(t *testing.T) {
	engine := NewEngine()

	// 1. Positive case: code_challenge_method: "plain"
	contentPositive := `const config = { client_id: "xyz", code_challenge_method: "plain" };`
	assetsPos := []crawler.Asset{{URL: "https://example.com/oauth.js", Content: []byte(contentPositive)}}
	_, findingsPos := engine.AnalyzeAuthentication(nil, assetsPos, http.Header{}, "https://example.com", "asm-1", "exec-1", "tgt-1")

	foundPKCEFinding := false
	for _, f := range findingsPos {
		if f.Category == "Authentication / OAuth PKCE" {
			foundPKCEFinding = true
			if f.Severity != "INFO" {
				t.Errorf("expected INFO severity for static PKCE finding, got %s", f.Severity)
			}
			if f.Verification.Status != "NOT_VERIFIED" {
				t.Errorf("expected NOT_VERIFIED verification status, got %s", f.Verification.Status)
			}
			if f.Score > 15 {
				t.Errorf("expected score <= 15, got %d", f.Score)
			}
		}
	}
	if !foundPKCEFinding {
		t.Errorf("expected PKCE plain finding to be generated")
	}

	// 2. Negative case: code_challenge_method: "S256"
	contentNeg := `const config = { client_id: "xyz", code_challenge_method: "S256" };`
	assetsNeg := []crawler.Asset{{URL: "https://example.com/oauth_secure.js", Content: []byte(contentNeg)}}
	_, findingsNeg := engine.AnalyzeAuthentication(nil, assetsNeg, http.Header{}, "https://example.com", "asm-1", "exec-1", "tgt-1")
	for _, f := range findingsNeg {
		if f.Category == "Authentication / OAuth PKCE" {
			t.Errorf("unexpected PKCE finding generated for S256 method: %+v", f)
		}
	}

	// 3. Ambiguous / Malformed input
	contentAmb := `const code_challenge_method = "unsupported_or_invalid";`
	assetsAmb := []crawler.Asset{{URL: "https://example.com/oauth_amb.js", Content: []byte(contentAmb)}}
	_, findingsAmb := engine.AnalyzeAuthentication(nil, assetsAmb, http.Header{}, "https://example.com", "asm-1", "exec-1", "tgt-1")
	for _, f := range findingsAmb {
		if f.Category == "Authentication / OAuth PKCE" {
			t.Errorf("unexpected PKCE finding for malformed method: %+v", f)
		}
	}
}

func TestAccuracy_FalsePositiveRoutesAndParameters(t *testing.T) {
	c := NewClassifier()

	// 1. Content/docs/editorial routes that should NOT be classified as auth
	falseRoutes := []string{
		"/blog/how-to-login-safely",
		"/docs/login-setup-guide",
		"/articles/auth-best-practices",
		"/authors/jothish",
		"/author/alice",
		"/authority/overview",
		"/images/login-button.png",
		"/static/css/login-styles.css",
		"/downloads/login-patch.zip",
	}
	for _, r := range falseRoutes {
		cat, _, matched, _ := c.ClassifyRoute(r)
		if matched && cat == CategoryLogin {
			t.Errorf("FALSE POSITIVE: Route %q was misclassified as CategoryLogin!", r)
		}
	}

	// 2. Generic parameter 'code' alone must NOT classify as OAuth/Session token refresh
	genericParams := []string{"code"}
	_, _, matchedG, _ := c.ClassifyFromParameters("/api/shipping", genericParams)
	if matchedG {
		t.Errorf("FALSE POSITIVE: Parameter 'code' alone misclassified endpoint as auth surface!")
	}

	// 3. Qualified OAuth parameters with 'code' and 'state' SHOULD classify as Session token refresh
	oauthParams := []string{"code", "state"}
	catO, subO, matchedO, _ := c.ClassifyFromParameters("/auth/callback", oauthParams)
	if !matchedO || catO != CategorySession || subO != SubtypeTokenRefresh {
		t.Errorf("expected OAuth callback params (code+state) to match Session/TokenRefresh: matched=%t, cat=%s", matchedO, catO)
	}
}

func TestRedaction_SyntheticSecretsAudit(t *testing.T) {
	engine := NewEngine()

	// Test secrets
	secretPass := "STAGE31_TEST_PASSWORD_9F3A"
	secretSess := "STAGE31_FAKE_SESSION_8B2D"
	secretRefr := "STAGE31_FAKE_REFRESH_TOKEN_4C7E"
	secretAPI := "STAGE31_FAKE_API_SECRET_6D1A"

	// Construct inputs embedding all 4 synthetic secrets
	targetURL := "https://example.com/portal?token=" + secretAPI
	headers := http.Header{}
	headers.Add("Set-Cookie", "session_id="+secretSess+"; Path=/; Secure") // Missing HttpOnly
	headers.Add("Set-Cookie", "refresh_token="+secretRefr+"; Path=/; Secure")

	jsPayload := `
		// Simulated JWT with embedded password in payload
		const jwt = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJwYXNzIjoi` + secretPass + `\"}.";
		const config = { code_challenge_method: "plain" };
	`
	assets := []crawler.Asset{
		{
			URL:     "https://example.com/assets/auth.js?secret=" + secretAPI,
			Content: []byte(jsPayload),
		},
	}

	authInv, findings := engine.AnalyzeAuthentication(nil, assets, headers, targetURL, "asm-sec", "exec-sec", "tgt-sec")

	// Audit all records in authInv
	for _, ck := range authInv.Cookies {
		if strings.Contains(ck.SourceURL, secretAPI) {
			t.Fatalf("LEAK: Secret leaked in Cookie.SourceURL: %s", ck.SourceURL)
		}
	}
	for _, tok := range authInv.Tokens {
		if strings.Contains(tok.SourceAsset, secretAPI) {
			t.Fatalf("LEAK: Secret leaked in Token.SourceAsset: %s", tok.SourceAsset)
		}
		if strings.Contains(tok.EvidenceSummary, secretPass) {
			t.Fatalf("LEAK: Secret leaked in Token.EvidenceSummary: %s", tok.EvidenceSummary)
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Target, secretAPI) || strings.Contains(f.Endpoint, secretAPI) {
			t.Fatalf("LEAK: Secret leaked in Finding URL: Target=%s Endpoint=%s", f.Target, f.Endpoint)
		}
		if strings.Contains(f.Evidence, secretSess) || strings.Contains(f.Evidence, secretRefr) ||
			strings.Contains(f.Evidence, secretPass) || strings.Contains(f.Evidence, secretAPI) {
			t.Fatalf("LEAK: Secret leaked in Finding Evidence: %s", f.Evidence)
		}
		if strings.Contains(f.Description, secretSess) || strings.Contains(f.Description, secretPass) {
			t.Fatalf("LEAK: Secret leaked in Finding Description: %s", f.Description)
		}
	}
}
