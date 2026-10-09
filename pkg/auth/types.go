package auth

import (
	"net/url"
	"strings"
	"time"
)

// SanitizeURL strips sensitive query parameter values from URL strings to prevent credential leakage.
func SanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	if len(q) == 0 {
		return rawURL
	}
	modified := false
	sensitiveKeys := map[string]struct{}{
		"token": {}, "access_token": {}, "refresh_token": {}, "id_token": {},
		"auth": {}, "auth_token": {}, "authorization": {}, "code": {},
		"secret": {}, "client_secret": {}, "api_key": {}, "apikey": {},
		"key": {}, "password": {}, "passwd": {}, "pass": {},
		"session": {}, "session_id": {}, "sessionid": {}, "sid": {},
		"sig": {}, "signature": {}, "credential": {}, "credentials": {},
	}
	for k := range q {
		lowerK := strings.ToLower(k)
		if _, ok := sensitiveKeys[lowerK]; ok || strings.Contains(lowerK, "token") || strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "pass") {
			q.Set(k, "[REDACTED]")
			modified = true
		}
	}
	if modified {
		parsed.RawQuery = q.Encode()
		return parsed.String()
	}
	return rawURL
}

// AuthCategory classifies the high-level authentication surface purpose.
type AuthCategory string

const (
	CategoryLogin             AuthCategory = "LOGIN"
	CategoryRegistration      AuthCategory = "REGISTRATION"
	CategoryPasswordReset     AuthCategory = "PASSWORD_RESET"
	CategoryMFA               AuthCategory = "MFA"
	CategorySession           AuthCategory = "SESSION"
	CategoryOAuthSSO          AuthCategory = "OAUTH_SSO"
	CategoryAlternative       AuthCategory = "ALTERNATIVE"
	CategoryProtectedEndpoint AuthCategory = "PROTECTED_ENDPOINT"
	CategoryUnknown           AuthCategory = "UNKNOWN"
)

// AuthSubtype specifies the concrete identity or flow mechanism.
type AuthSubtype string

const (
	SubtypePassword        AuthSubtype = "PASSWORD"
	SubtypeOAuthOIDC       AuthSubtype = "OAUTH_OIDC"
	SubtypeSAML            AuthSubtype = "SAML"
	SubtypeMagicLink       AuthSubtype = "MAGIC_LINK"
	SubtypeWebAuthnPasskey AuthSubtype = "WEBAUTHN_PASSKEY"
	SubtypeTOTP            AuthSubtype = "TOTP"
	SubtypeSMSOTP          AuthSubtype = "SMS_OTP"
	SubtypeEmailOTP        AuthSubtype = "EMAIL_OTP"
	SubtypeTokenRefresh    AuthSubtype = "TOKEN_REFRESH"
	SubtypeLogout          AuthSubtype = "LOGOUT"
	SubtypeSessionStatus   AuthSubtype = "SESSION_STATUS"
	SubtypePKCE            AuthSubtype = "PKCE"
	SubtypeCSRF            AuthSubtype = "CSRF"
	SubtypeBearerToken     AuthSubtype = "BEARER_TOKEN"
	SubtypeUnknown         AuthSubtype = "UNKNOWN"
)

// AuthState describes the observed or inferred access/authentication state.
type AuthState string

const (
	AuthStateUnknown              AuthState = "UNKNOWN"
	AuthStateAnonymousObserved    AuthState = "ANONYMOUS_OBSERVED"
	AuthStateIndicatorPresent     AuthState = "AUTHENTICATION_INDICATOR_PRESENT"
	AuthStateUnverified           AuthState = "AUTHENTICATED_STATE_UNVERIFIED"
	AuthStateConfirmed            AuthState = "AUTHENTICATED_STATE_CONFIRMED"
	AuthStateExpiredConfirmed     AuthState = "EXPIRED_OR_INVALID_STATE_CONFIRMED"
)

// Confidence denotes evidence certainty.
type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

// VerificationStatus denotes the procedural verification state of an authentication surface.
type VerificationStatus string

const (
	VerificationDiscovered   VerificationStatus = "DISCOVERED"
	VerificationInferred     VerificationStatus = "INFERRED"
	VerificationVerified     VerificationStatus = "VERIFIED"
	VerificationContradicted VerificationStatus = "CONTRADICTED"
	VerificationUnknown      VerificationStatus = "UNKNOWN"
)

// CookiePurpose categorizes the functional role of an HTTP cookie.
type CookiePurpose string

const (
	CookiePurposeSession     CookiePurpose = "SESSION"
	CookiePurposeAuthToken   CookiePurpose = "AUTH_TOKEN"
	CookiePurposeCSRF        CookiePurpose = "CSRF"
	CookiePurposePreference  CookiePurpose = "PREFERENCE"
	CookiePurposeTracking    CookiePurpose = "TRACKING"
	CookiePurposeUnknown     CookiePurpose = "UNKNOWN"
)

// AuthSurface represents an identified identity entrypoint, route, form, or mechanism.
type AuthSurface struct {
	ID                 string             `json:"id"`
	AssessmentID       string             `json:"assessment_id"`
	ExecutionID        string             `json:"execution_id,omitempty"`
	TargetID           string             `json:"target_id,omitempty"`
	CanonicalID        string             `json:"canonical_id"`
	Category           AuthCategory       `json:"category"`
	Subtype            AuthSubtype        `json:"subtype"`
	Identifier         string             `json:"identifier"` // Normalized Route, Action URL, or Flow Name
	EndpointID         string             `json:"endpoint_id,omitempty"`
	AppID              string             `json:"app_id,omitempty"`
	DiscoveryMethod    string             `json:"discovery_method"` // HTML_FORM, ROUTE_NAMING, PARAM_HEURISTIC, JS_SDK, HEADER
	Confidence         Confidence         `json:"confidence"`
	VerificationStatus VerificationStatus `json:"verification_status"`
	AuthState          AuthState          `json:"auth_state"`
	InScope            bool               `json:"in_scope"`
	Explanation        string             `json:"explanation"`
	Evidence           map[string]any     `json:"evidence"`
	Metadata           map[string]any     `json:"metadata"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// CookieMetadata records passively observed cookie attributes without storing values.
type CookieMetadata struct {
	ID                string        `json:"id"`
	AssessmentID      string        `json:"assessment_id"`
	ExecutionID       string        `json:"execution_id,omitempty"`
	TargetID          string        `json:"target_id,omitempty"`
	Name              string        `json:"name"`
	Domain            string        `json:"domain,omitempty"`
	Path              string        `json:"path,omitempty"`
	IsSecure          bool          `json:"is_secure"`
	IsHTTPOnly        bool          `json:"is_http_only"`
	SameSite          string        `json:"same_site"` // Strict, Lax, None, Unset
	MaxAge            int           `json:"max_age,omitempty"`
	Expires           string        `json:"expires,omitempty"`
	Purpose           CookiePurpose `json:"purpose"`
	IsSession         bool          `json:"is_session"`
	HasSecurityIssue  bool          `json:"has_security_issue"`
	SecurityDefects   []string      `json:"security_defects,omitempty"`
	SourceURL         string        `json:"source_url"`
	CreatedAt         time.Time     `json:"created_at"`
}

// TokenArtifact records non-secret token structure observations.
type TokenArtifact struct {
	ID              string      `json:"id"`
	AssessmentID    string      `json:"assessment_id"`
	ExecutionID     string      `json:"execution_id,omitempty"`
	TargetID        string      `json:"target_id,omitempty"`
	TokenType       string      `json:"token_type"` // JWT, PKCE_CHALLENGE, CSRF, OAUTH_TOKEN, RECOVERY_TOKEN
	Subtype         AuthSubtype `json:"subtype"`
	Name            string      `json:"name"`     // Parameter or header name
	Location        string      `json:"location"` // HEADER, QUERY, BODY, SCRIPT
	Format          string      `json:"format"`   // JWT_3_PART, HEX, BASE64, OPAQUE
	Algorithm       string      `json:"algorithm,omitempty"` // E.g. RS256, HS256, none (from unverified header)
	EvidenceSummary string      `json:"evidence_summary"`
	SourceAsset     string      `json:"source_asset"`
	CreatedAt       time.Time   `json:"created_at"`
}

// ProtectedEndpointInfo records protection evidence correlated with Stage 2 endpoints.
type ProtectedEndpointInfo struct {
	EndpointPath       string             `json:"endpoint_path"`
	Method             string             `json:"method"`
	ObservedStatus     int                `json:"observed_status"` // E.g. 401, 403, 200, 302
	AuthChallenge      string             `json:"auth_challenge,omitempty"` // E.g. Bearer realm=...
	ProtectionStatus   string             `json:"protection_status"` // CONFIRMED_PROTECTED, INFERRED_PROTECTED, ANONYMOUS_ACCESSIBLE, UNKNOWN
	AssociatedSurfaces []string           `json:"associated_surfaces,omitempty"`
	Confidence         Confidence         `json:"confidence"`
	Explanation        string             `json:"explanation"`
}

// AuthInventory holds all authentication intelligence artifacts for an assessment execution.
type AuthInventory struct {
	Surfaces           []AuthSurface           `json:"surfaces"`
	Cookies            []CookieMetadata        `json:"cookies"`
	Tokens             []TokenArtifact         `json:"tokens"`
	ProtectedEndpoints []ProtectedEndpointInfo `json:"protected_endpoints"`
}

// AuthSummary provides aggregated metrics for CLI display and reports.
type AuthSummary struct {
	TotalSurfaces      int            `json:"total_surfaces"`
	SurfacesByCategory map[string]int `json:"surfaces_by_category"`
	TotalCookies       int            `json:"total_cookies"`
	SessionCookies     int            `json:"session_cookies"`
	InsecureCookies    int            `json:"insecure_cookies"`
	TotalTokens        int            `json:"total_tokens"`
	ProtectedEndpoints int            `json:"protected_endpoints"`
}
