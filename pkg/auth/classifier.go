package auth

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// Known Auth SDK and client library signatures
	supabaseAuthRegex = regexp.MustCompile(`(?i)(?:@supabase/gotrue-js|supabase\.auth|gotrue_meta_security)`)
	firebaseAuthRegex = regexp.MustCompile(`(?i)(?:firebase/auth|signInWithEmailAndPassword|createUserWithEmailAndPassword)`)
	nextAuthRegex     = regexp.MustCompile(`(?i)(?:next-auth|/api/auth/(?:signin|signout|callback|session|providers|csrf))`)
	clerkAuthRegex    = regexp.MustCompile(`(?i)(?:@clerk/clerk-react|@clerk/nextjs|clerk\.session)`)
	auth0Regex        = regexp.MustCompile(`(?i)(?:@auth0/auth0-spa-js|auth0\.client)`)
	webAuthnRegex     = regexp.MustCompile(`(?i)(?:navigator\.credentials\.get|navigator\.credentials\.create|webauthn)`)
)

// Classifier determines the authentication categories, subtypes, and confidence from diverse signals.
type Classifier struct{}

// NewClassifier creates an authentication classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// ClassifyRoute evaluates whether a URL path represents an authentication surface.
func (c *Classifier) ClassifyRoute(rawPath string) (AuthCategory, AuthSubtype, bool, string) {
	clean := strings.ToLower(strings.TrimSpace(rawPath))
	if clean == "" || clean == "/" {
		return "", "", false, ""
	}

	// 1. Password Reset & Recovery
	if strings.Contains(clean, "forgot-password") || strings.Contains(clean, "reset-password") ||
		strings.Contains(clean, "password-reset") || strings.Contains(clean, "/recovery") ||
		strings.Contains(clean, "recover-password") {
		return CategoryPasswordReset, SubtypePassword, true, "Route name indicates password recovery or reset flow"
	}

	// 2. Multi-Factor Authentication
	if strings.Contains(clean, "/mfa") || strings.Contains(clean, "/2fa") ||
		strings.Contains(clean, "/otp") || strings.Contains(clean, "/authenticator") ||
		strings.Contains(clean, "/webauthn") || strings.Contains(clean, "/passkey") {
		subtype := SubtypeTOTP
		if strings.Contains(clean, "webauthn") || strings.Contains(clean, "passkey") {
			subtype = SubtypeWebAuthnPasskey
		} else if strings.Contains(clean, "sms") {
			subtype = SubtypeSMSOTP
		} else if strings.Contains(clean, "email") {
			subtype = SubtypeEmailOTP
		}
		return CategoryMFA, subtype, true, "Route name matches multi-factor authentication or verification taxonomy"
	}

	// 3. Logout & Session Termination
	if strings.Contains(clean, "logout") || strings.Contains(clean, "signout") || strings.Contains(clean, "sign-out") {
		return CategorySession, SubtypeLogout, true, "Route name indicates user session termination / logout"
	}

	// 4. Session Status & Token Refresh
	if strings.Contains(clean, "/auth/session") || strings.Contains(clean, "/whoami") || strings.Contains(clean, "/auth/me") {
		return CategorySession, SubtypeSessionStatus, true, "Route name indicates active session status or current-user query"
	}
	if strings.Contains(clean, "/token/refresh") || strings.Contains(clean, "/auth/refresh") || strings.Contains(clean, "/oauth/token") {
		return CategorySession, SubtypeTokenRefresh, true, "Route name indicates token issuance or session refresh endpoint"
	}

	// 5. Registration
	if strings.Contains(clean, "register") || strings.Contains(clean, "signup") ||
		strings.Contains(clean, "sign-up") || strings.Contains(clean, "create-account") ||
		strings.Contains(clean, "enroll") {
		return CategoryRegistration, SubtypePassword, true, "Route name indicates account registration / enrollment"
	}

	// 6. Alternative Auth (OAuth/OIDC/SAML/MagicLink)
	if strings.Contains(clean, "/oauth") || strings.Contains(clean, "/oidc") ||
		strings.Contains(clean, "/saml") || strings.Contains(clean, "/auth/google") ||
		strings.Contains(clean, "/auth/github") || strings.Contains(clean, "/auth/microsoft") {
		subtype := SubtypeOAuthOIDC
		if strings.Contains(clean, "saml") {
			subtype = SubtypeSAML
		}
		return CategoryOAuthSSO, subtype, true, "Route matches federated identity or SSO provider pattern"
	}
	if strings.Contains(clean, "magic-link") || strings.Contains(clean, "magiclink") || strings.Contains(clean, "passwordless") {
		return CategoryAlternative, SubtypeMagicLink, true, "Route matches passwordless or magic-link flow"
	}

	// 7. Login
	if strings.Contains(clean, "login") || strings.Contains(clean, "signin") ||
		strings.Contains(clean, "sign-in") || strings.Contains(clean, "/auth") {
		// Verify /auth is not just general docs
		if clean == "/auth" || strings.HasPrefix(clean, "/auth/") || strings.Contains(clean, "login") || strings.Contains(clean, "signin") {
			return CategoryLogin, SubtypePassword, true, "Route name indicates user authentication / login entrypoint"
		}
	}

	return "", "", false, ""
}

// ClassifyFromParameters evaluates whether an endpoint represents an authentication surface based on parameter taxonomy.
// This resolves the gap where client-side SDK endpoints (like /api/broadcast or /auth/v1) expose auth parameters without explicit route names.
func (c *Classifier) ClassifyFromParameters(endpointPath string, paramNames []string) (AuthCategory, AuthSubtype, bool, string) {
	hasPassword := false
	hasEmailOrUser := false
	hasResetToken := false
	hasMFAOrOTP := false
	hasWebAuthn := false
	hasOAuthToken := false
	hasPKCE := false

	for _, name := range paramNames {
		lower := strings.ToLower(name)
		switch {
		case lower == "password" || lower == "pass" || lower == "passwd":
			hasPassword = true
		case lower == "email" || lower == "username" || lower == "login":
			hasEmailOrUser = true
		case strings.Contains(lower, "reset") || strings.Contains(lower, "recovery") || lower == "hashed_token":
			hasResetToken = true
		case lower == "otp" || lower == "totp" || lower == "email_otp" || lower == "factorid" || strings.Contains(lower, "factors"):
			hasMFAOrOTP = true
		case strings.Contains(lower, "webauthn") || strings.Contains(lower, "passkey") || lower == "credential_response":
			hasWebAuthn = true
		case lower == "access_token" || lower == "refresh_token" || lower == "id_token" || lower == "code":
			hasOAuthToken = true
		case lower == "code_challenge" || lower == "code_verifier":
			hasPKCE = true
		}
	}

	// Password reset endpoint inferred from parameters
	if hasResetToken && hasPassword {
		return CategoryPasswordReset, SubtypePassword, true, "Endpoint accepts recovery token and new password parameters"
	}

	// WebAuthn / Passkey surface
	if hasWebAuthn {
		return CategoryMFA, SubtypeWebAuthnPasskey, true, "Endpoint accepts WebAuthn/Passkey credential assertions"
	}

	// MFA verification endpoint
	if hasMFAOrOTP {
		return CategoryMFA, SubtypeTOTP, true, "Endpoint accepts multi-factor authentication (OTP/factorId) parameters"
	}

	// Direct credential authentication endpoint
	if hasPassword && hasEmailOrUser {
		return CategoryLogin, SubtypePassword, true, "Endpoint accepts credential payload (username/email and password)"
	}

	// Session refresh / token exchange endpoint
	if hasOAuthToken || hasPKCE {
		return CategorySession, SubtypeTokenRefresh, true, "Endpoint accepts OAuth/PKCE token exchange or refresh parameters"
	}

	return "", "", false, ""
}

// ClassifyScriptSDK inspects JavaScript assets for known authentication SDKs.
func (c *Classifier) ClassifyScriptSDK(jsContent string, sourceAsset, asmID, execID, targetID, appID string) []AuthSurface {
	var surfaces []AuthSurface

	addSDKSurface := func(cat AuthCategory, sub AuthSubtype, name, evidence string) {
		canonicalID := fmt.Sprintf("SDK:%s:%s", name, sourceAsset)
		surfaces = append(surfaces, AuthSurface{
			ID:                 uuid.New().String(),
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			CanonicalID:        canonicalID,
			Category:           cat,
			Subtype:            sub,
			Identifier:         name,
			AppID:              appID,
			DiscoveryMethod:    "JS_SDK_SIGNATURE",
			Confidence:         ConfidenceHigh,
			VerificationStatus: VerificationInferred,
			AuthState:          AuthStateIndicatorPresent,
			InScope:            true,
			Explanation:        fmt.Sprintf("Recognized %s client authentication SDK in bundle %s", name, sourceAsset),
			Evidence: map[string]any{
				"sdk":          name,
				"evidence":     evidence,
				"source_asset": sourceAsset,
			},
			Metadata: map[string]any{
				"library": name,
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
	}

	if supabaseAuthRegex.MatchString(jsContent) {
		addSDKSurface(CategoryLogin, SubtypePassword, "Supabase GoTrue Auth", "Supabase GoTrue client authentication signature detected")
	}

	if firebaseAuthRegex.MatchString(jsContent) {
		addSDKSurface(CategoryLogin, SubtypePassword, "Firebase Auth", "Firebase client authentication functions detected")
	}

	if nextAuthRegex.MatchString(jsContent) {
		addSDKSurface(CategorySession, SubtypeSessionStatus, "NextAuth.js", "NextAuth session management and authentication route handlers detected")
	}

	if clerkAuthRegex.MatchString(jsContent) {
		addSDKSurface(CategoryLogin, SubtypeOAuthOIDC, "Clerk Auth", "Clerk identity and session management components detected")
	}

	if auth0Regex.MatchString(jsContent) {
		addSDKSurface(CategoryOAuthSSO, SubtypeOAuthOIDC, "Auth0 SPA", "Auth0 client authentication SDK detected")
	}

	if webAuthnRegex.MatchString(jsContent) {
		addSDKSurface(CategoryAlternative, SubtypeWebAuthnPasskey, "WebAuthn / Passkeys", "Browser navigator.credentials WebAuthn API invocation detected")
	}

	return surfaces
}
