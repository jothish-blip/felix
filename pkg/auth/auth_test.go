package auth

import (
	"net/http"
	"net/http/httptest"
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
	if p2.ProtectionStatus != "CONFIRMED_PROTECTED" {
		t.Errorf("expected CONFIRMED_PROTECTED, got: %s", p2.ProtectionStatus)
	}

	// 302 Redirect to /login
	p3 := classifier.EvaluateEndpointProtection("/dashboard", "GET", 302, "", "/auth/login", []string{})
	if p3.ProtectionStatus != "INFERRED_PROTECTED" {
		t.Errorf("expected INFERRED_PROTECTED, got: %s", p3.ProtectionStatus)
	}

	// 200 OK on anonymous route
	p4 := classifier.EvaluateEndpointProtection("/public", "GET", 200, "", "", []string{})
	if p4.ProtectionStatus != "ANONYMOUS_ACCESSIBLE" {
		t.Errorf("expected ANONYMOUS_ACCESSIBLE, got: %s", p4.ProtectionStatus)
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
