package discovery

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuthSurfaceType categorizes the specific identity or authentication mechanism.
type AuthSurfaceType string

const (
	AuthTypeLogin          AuthSurfaceType = "LOGIN"
	AuthTypeRegistration   AuthSurfaceType = "REGISTRATION"
	AuthTypePasswordReset  AuthSurfaceType = "PASSWORD_RESET"
	AuthTypeMFA            AuthSurfaceType = "MFA_2FA"
	AuthTypeSSOOAuth       AuthSurfaceType = "SSO_OAUTH"
	AuthTypeSession        AuthSurfaceType = "SESSION_MANAGEMENT"
	AuthTypeLogout         AuthSurfaceType = "LOGOUT"
	AuthTypeTokenEndpoint  AuthSurfaceType = "TOKEN_ENDPOINT"
	AuthTypeUnknown        AuthSurfaceType = "UNKNOWN_AUTH"
)

var (
	// Regex matching OAuth / OIDC client configurations in JS
	oidcConfigRegex = regexp.MustCompile(`(?i)(?:clientId|client_id|authority|redirect_uri|redirectUri)\s*:\s*["']([^"'\s]+)["']`)
	// Regex identifying OAuth / IdP authorization endpoints
	oauthEndpointRegex = regexp.MustCompile(`(?i)(?:/oauth2?/(?:v[0-9]+/)?(?:authorize|token|callback)|/\.well-known/openid-configuration|/saml/(?:login|sso|metadata))`)
)

// DiscoveredAuthSurface represents an identified identity or authentication entry point.
type DiscoveredAuthSurface struct {
	SurfaceType AuthSurfaceType `json:"surface_type"`
	Identifier  string          `json:"identifier"` // URL, Route, or Flow Name
	Method      string          `json:"method"`
	Source      string          `json:"source"`     // FORM, ROUTE, LINK, OIDC_CONFIG, API
	Observed    bool            `json:"observed"`   // true if directly seen in HTML/Form, false if inferred from JS/regex
	Evidence    string          `json:"evidence"`
	Details     map[string]any  `json:"details,omitempty"`
}

// AuthSurfaceExtractor identifies authentication and identity surfaces defensively.
type AuthSurfaceExtractor struct{}

// NewAuthSurfaceExtractor creates an AuthSurfaceExtractor instance.
func NewAuthSurfaceExtractor() *AuthSurfaceExtractor {
	return &AuthSurfaceExtractor{}
}

// ClassifyAuthRoute analyzes a URL path to determine if it is an authentication surface.
func ClassifyAuthRoute(rawPath string) (AuthSurfaceType, bool) {
	clean := strings.ToLower(strings.TrimSpace(rawPath))
	if clean == "" || clean == "/" {
		return "", false
	}

	// Token endpoints
	if strings.Contains(clean, "/token") || strings.Contains(clean, "/refresh") || strings.Contains(clean, "/jwt") {
		return AuthTypeTokenEndpoint, true
	}

	// SSO & OAuth
	if oauthEndpointRegex.MatchString(clean) || strings.Contains(clean, "/auth/google") ||
		strings.Contains(clean, "/auth/github") || strings.Contains(clean, "/auth/microsoft") ||
		strings.Contains(clean, "/saml") || strings.Contains(clean, "/oidc") {
		return AuthTypeSSOOAuth, true
	}

	// MFA
	if strings.Contains(clean, "/mfa") || strings.Contains(clean, "/2fa") ||
		strings.Contains(clean, "/otp") || strings.Contains(clean, "/authenticator") {
		return AuthTypeMFA, true
	}

	// Logout
	if strings.Contains(clean, "logout") || strings.Contains(clean, "signout") || strings.Contains(clean, "sign-out") {
		return AuthTypeLogout, true
	}

	// Password reset
	if strings.Contains(clean, "forgot-password") || strings.Contains(clean, "reset-password") ||
		strings.Contains(clean, "password-reset") || strings.Contains(clean, "recovery") {
		return AuthTypePasswordReset, true
	}

	// Registration
	if strings.Contains(clean, "register") || strings.Contains(clean, "signup") ||
		strings.Contains(clean, "sign-up") || strings.Contains(clean, "create-account") {
		return AuthTypeRegistration, true
	}

	// Login
	if strings.Contains(clean, "login") || strings.Contains(clean, "signin") ||
		strings.Contains(clean, "sign-in") || strings.Contains(clean, "/auth/login") {
		return AuthTypeLogin, true
	}

	// Session
	if strings.Contains(clean, "/auth/session") || strings.Contains(clean, "/whoami") || strings.Contains(clean, "/auth/me") {
		return AuthTypeSession, true
	}

	return "", false
}

// ExtractFromForms inspects discovered HTML forms for authentication surfaces.
func (ase *AuthSurfaceExtractor) ExtractFromForms(forms []DiscoveredForm) []DiscoveredAuthSurface {
	var surfaces []DiscoveredAuthSurface

	for _, f := range forms {
		switch f.Purpose {
		case "LOGIN":
			surfaces = append(surfaces, DiscoveredAuthSurface{
				SurfaceType: AuthTypeLogin,
				Identifier:  f.Action,
				Method:      f.Method,
				Source:      "HTML_FORM",
				Observed:    true,
				Evidence:    fmt.Sprintf("HTML login form posting to %s with password field", f.Action),
				Details: map[string]any{
					"source_page": f.SourcePage,
					"enctype":     f.Enctype,
				},
			})
		case "REGISTRATION":
			surfaces = append(surfaces, DiscoveredAuthSurface{
				SurfaceType: AuthTypeRegistration,
				Identifier:  f.Action,
				Method:      f.Method,
				Source:      "HTML_FORM",
				Observed:    true,
				Evidence:    fmt.Sprintf("HTML registration form posting to %s", f.Action),
				Details: map[string]any{
					"source_page": f.SourcePage,
				},
			})
		case "PASSWORD_RESET":
			surfaces = append(surfaces, DiscoveredAuthSurface{
				SurfaceType: AuthTypePasswordReset,
				Identifier:  f.Action,
				Method:      f.Method,
				Source:      "HTML_FORM",
				Observed:    true,
				Evidence:    fmt.Sprintf("HTML password reset form posting to %s", f.Action),
				Details: map[string]any{
					"source_page": f.SourcePage,
				},
			})
		}
	}

	return surfaces
}

// ExtractFromJS inspects JavaScript content for OIDC/OAuth references or auth configurations.
func (ase *AuthSurfaceExtractor) ExtractFromJS(jsContent, sourceAsset string) []DiscoveredAuthSurface {
	var surfaces []DiscoveredAuthSurface

	if oidcConfigRegex.MatchString(jsContent) {
		matches := oidcConfigRegex.FindAllStringSubmatch(jsContent, -1)
		cfgDetails := make(map[string]any)
		for _, m := range matches {
			if len(m) > 1 {
				val := m[1]
				if strings.HasPrefix(val, "http") || strings.HasPrefix(val, "/") {
					cfgDetails["auth_url"] = val
				}
			}
		}

		surfaces = append(surfaces, DiscoveredAuthSurface{
			SurfaceType: AuthTypeSSOOAuth,
			Identifier:  sourceAsset,
			Method:      "GET",
			Source:      "JS_OIDC_CONFIG",
			Observed:    false,
			Evidence:    fmt.Sprintf("OAuth/OIDC configuration identifiers detected in JavaScript asset %s", sourceAsset),
			Details:     cfgDetails,
		})
	}

	return surfaces
}

// IngestAuthSurfaces registers authentication surfaces as inventory assets and links them to the application.
func (ase *AuthSurfaceExtractor) IngestAuthSurfaces(
	inv *Inventory,
	asmID, execID, targetID string,
	appAssetID string,
	surfaces []DiscoveredAuthSurface,
) []string {
	var surfaceIDs []string
	seen := make(map[string]struct{})

	for _, s := range surfaces {
		cleanID := strings.TrimSpace(s.Identifier)
		canonicalID := fmt.Sprintf("%s:%s", s.SurfaceType, cleanID)

		if _, exists := seen[canonicalID]; exists {
			continue
		}
		seen[canonicalID] = struct{}{}

		status := StatusObserved
		if !s.Observed {
			status = StatusInferred
		}

		asset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeAuthSurface,
			CanonicalID:     canonicalID,
			ParentID:        appAssetID,
			DisplayName:     fmt.Sprintf("Auth Surface [%s] %s", s.SurfaceType, cleanID),
			SourceAsset:     s.Identifier,
			DiscoveryMethod: s.Source,
			DiscoveryStatus: status,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"surface_type": string(s.SurfaceType),
				"identifier":   cleanID,
				"method":       s.Method,
				"source":       s.Source,
				"observed":     s.Observed,
				"details":      s.Details,
			},
			Evidence: map[string]any{
				"evidence": s.Evidence,
				"source":   s.Source,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		sID := inv.AddAsset(asset)
		surfaceIDs = append(surfaceIDs, sID)

		// Link Application EXPOSES_AUTH_SURFACE AuthSurface
		if appAssetID != "" {
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: appAssetID,
				TargetAssetID: sID,
				RelationType:  RelExposesAuthSurface,
				Evidence:      s.Evidence,
				Confidence:    ConfidenceHigh,
			})
		}
	}

	return surfaceIDs
}
