package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// Regex identifying 3-part base64url JWT tokens
	jwtRegex = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

	// Regex identifying PKCE parameters in code/requests
	pkceMethodRegex = regexp.MustCompile(`(?i)(?:code_challenge_method|codeChallengeMethod)\s*[:=]\s*["']?(S256|plain)["']?`)
	pkceChallengeRegex = regexp.MustCompile(`(?i)(?:code_challenge|codeChallenge)\b`)
	pkceVerifierRegex = regexp.MustCompile(`(?i)(?:code_verifier|codeVerifier)\b`)

	// Regex identifying OAuth / Bearer token flows
	oauthTokenParamRegex = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|auth_code)\b`)

	// Regex identifying CSRF tokens
	csrfParamRegex = regexp.MustCompile(`(?i)\b(csrf_token|xsrf_token|anti_forgery_token|_csrf)\b`)

	// Regex identifying password recovery tokens
	recoveryParamRegex = regexp.MustCompile(`(?i)\b(reset_token|recovery_token|magic_token|password_reset_code)\b`)
)

// ExtractAndAnalyzeTokens scans content (scripts, headers, parameters) for token architectures.
// Guarantees: Raw token secrets are never persisted; only structural formats and algorithms are captured.
func ExtractAndAnalyzeTokens(content, sourceAsset, asmID, execID, targetID string) []TokenArtifact {
	var artifacts []TokenArtifact
	seen := make(map[string]struct{})

	addArtifact := func(art TokenArtifact) {
		key := fmt.Sprintf("%s:%s:%s", art.TokenType, art.Name, art.Location)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			artifacts = append(artifacts, art)
		}
	}

	// 1. JWT Analysis
	jwtMatches := jwtRegex.FindAllString(content, -1)
	for _, jwt := range jwtMatches {
		parts := strings.Split(jwt, ".")
		if len(parts) == 3 {
			// Safely inspect header only
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				// Retry standard base64 if needed
				headerJSON, _ = base64.URLEncoding.DecodeString(parts[0])
			}

			alg := "unknown"
			typ := "JWT"
			if len(headerJSON) > 0 {
				var headerMap map[string]any
				if err := json.Unmarshal(headerJSON, &headerMap); err == nil {
					if a, ok := headerMap["alg"].(string); ok {
						alg = a
					}
					if t, ok := headerMap["typ"].(string); ok {
						typ = t
					}
				}
			}

			summary := fmt.Sprintf("Observed %s structure with algorithm %s", typ, alg)
			if strings.EqualFold(alg, "none") {
				summary = "WARNING: JWT structure with 'none' algorithm detected"
			}

			addArtifact(TokenArtifact{
				ID:              uuid.New().String(),
				AssessmentID:    asmID,
				ExecutionID:     execID,
				TargetID:        targetID,
				TokenType:       "JWT",
				Subtype:         SubtypeBearerToken,
				Name:            "jwt_bearer",
				Location:        "SCRIPT",
				Format:          "JWT_3_PART",
				Algorithm:       alg,
				EvidenceSummary: summary,
				SourceAsset:     sourceAsset,
				CreatedAt:       time.Now().UTC(),
			})
		}
	}

	// 2. PKCE Analysis
	hasPKCEChallenge := pkceChallengeRegex.MatchString(content)
	hasPKCEVerifier := pkceVerifierRegex.MatchString(content)
	methodMatch := pkceMethodRegex.FindStringSubmatch(content)

	if hasPKCEChallenge || hasPKCEVerifier || len(methodMatch) > 1 {
		method := "S256"
		if len(methodMatch) > 1 {
			method = strings.ToUpper(methodMatch[1])
		}

		summary := fmt.Sprintf("PKCE flow identified (Method: %s)", method)
		if method == "PLAIN" {
			summary = "PKCE flow using insecure 'plain' code_challenge_method"
		}

		addArtifact(TokenArtifact{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			TokenType:       "PKCE",
			Subtype:         SubtypePKCE,
			Name:            "code_challenge",
			Location:        "BODY_OR_PARAM",
			Format:          method,
			Algorithm:       method,
			EvidenceSummary: summary,
			SourceAsset:     sourceAsset,
			CreatedAt:       time.Now().UTC(),
		})
	}

	// 3. OAuth Token Parameters
	for _, m := range oauthTokenParamRegex.FindAllString(content, -1) {
		tokenName := strings.ToLower(m)
		addArtifact(TokenArtifact{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			TokenType:       "OAUTH_TOKEN",
			Subtype:         SubtypeOAuthOIDC,
			Name:            tokenName,
			Location:        "PARAM_DECLARATION",
			Format:          "OPAQUE",
			EvidenceSummary: fmt.Sprintf("OAuth/OIDC token parameter '%s' declared in client flow", tokenName),
			SourceAsset:     sourceAsset,
			CreatedAt:       time.Now().UTC(),
		})
	}

	// 4. CSRF Token Parameters
	for _, m := range csrfParamRegex.FindAllString(content, -1) {
		tokenName := strings.ToLower(m)
		addArtifact(TokenArtifact{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			TokenType:       "CSRF_TOKEN",
			Subtype:         SubtypeCSRF,
			Name:            tokenName,
			Location:        "PARAM_DECLARATION",
			Format:          "OPAQUE",
			EvidenceSummary: fmt.Sprintf("Anti-CSRF parameter '%s' declared in request flow", tokenName),
			SourceAsset:     sourceAsset,
			CreatedAt:       time.Now().UTC(),
		})
	}

	// 5. Password Recovery Tokens
	for _, m := range recoveryParamRegex.FindAllString(content, -1) {
		tokenName := strings.ToLower(m)
		addArtifact(TokenArtifact{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			TokenType:       "RECOVERY_TOKEN",
			Subtype:         SubtypePassword,
			Name:            tokenName,
			Location:        "PARAM_DECLARATION",
			Format:          "OPAQUE",
			EvidenceSummary: fmt.Sprintf("Account recovery token parameter '%s' observed", tokenName),
			SourceAsset:     sourceAsset,
			CreatedAt:       time.Now().UTC(),
		})
	}

	return artifacts
}
