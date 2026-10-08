package secrets

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// Pattern defines a regular-expression signature and classification rules for a secret type.
type Pattern struct {
	Name       string
	Type       SecretType
	Regex      *regexp.Regexp
	Severity   string
	Confidence string
	Validator  func(match string) (bool, SecretType, string, string, string) // (keep, type, title, severity, confidence)
}

// DefaultPatterns returns the pre-compiled registry of high-confidence secret signatures.
func DefaultPatterns() []Pattern {
	return []Pattern{
		// 1. AWS Access Key ID
		{
			Name:       "AWS Access Key ID",
			Type:       SecretAWSAccessKey,
			Regex:      regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
		},

		// 2. Stripe Live Secret Key
		{
			Name:       "Stripe Live Secret Key",
			Type:       SecretStripeLiveKey,
			Regex:      regexp.MustCompile(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`),
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
			Validator: func(match string) (bool, SecretType, string, string, string) {
				// Ensure it's not a test key
				if strings.HasPrefix(match, "sk_test_") || strings.HasPrefix(match, "pk_") {
					return false, "", "", "", ""
				}
				return true, SecretStripeLiveKey, "Stripe Live Secret Key", SeverityHigh, ConfidenceHigh
			},
		},

		// 3. GitHub Personal Access Token (classic & fine-grained)
		{
			Name:       "GitHub Personal Access Token",
			Type:       SecretGitHubToken,
			Regex:      regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b`),
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
		},

		// 4. Slack Bot Token
		{
			Name:       "Slack Bot Token",
			Type:       SecretSlackToken,
			Regex:      regexp.MustCompile(`\b(xoxb-[0-9a-zA-Z-]{20,})\b`),
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
		},

		// 5. OpenAI API Key
		{
			Name:       "OpenAI API Key",
			Type:       SecretOpenAIKey,
			Regex:      regexp.MustCompile(`\b(sk-proj-[a-zA-Z0-9_\-]{48,}|sk-[a-zA-Z0-9]{48})\b`),
			Severity:   SeverityHigh,
			Confidence: ConfidenceHigh,
		},

		// 6. Private Cryptographic Keys
		{
			Name:       "Private Cryptographic Key",
			Type:       SecretPrivateKey,
			Regex:      regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----`),
			Severity:   SeverityCritical,
			Confidence: ConfidenceHigh,
		},

		// 7. JWT Tokens & Supabase Analysis
		{
			Name:       "JSON Web Token (JWT)",
			Type:       SecretJWT,
			Regex:      regexp.MustCompile(`\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Validator:  validateAndInspectJWT,
		},
	}
}

// validateAndInspectJWT decodes JWT claims safely to distinguish privileged keys
// (e.g. Supabase service_role) from public tokens (e.g. Supabase anon keys).
func validateAndInspectJWT(token string) (bool, SecretType, string, string, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, "", "", "", ""
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		// If base64url payload cannot be decoded, treat as unconfirmed JWT candidate
		return true, SecretJWT, "Unverified JWT Token", SeverityLow, ConfidenceLow
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return true, SecretJWT, "Malformed JWT Token", SeverityLow, ConfidenceLow
	}

	// Supabase Key Analysis
	iss, _ := claims["iss"].(string)
	role, _ := claims["role"].(string)
	isSupabase := strings.Contains(strings.ToLower(iss), "supabase") || strings.Contains(strings.ToLower(token), "supabase")

	if isSupabase || role != "" {
		if role == "service_role" {
			return true, SecretSupabaseServiceKey, "Supabase Service Role Secret Key", SeverityCritical, ConfidenceHigh
		}
		if role == "anon" {
			// Supabase anon keys are public client-side keys and NOT reported as privileged secrets
			return false, "", "", "", ""
		}
	}

	// General JWT: Check for privileged claims
	if role == "admin" || claims["admin"] == true {
		return true, SecretJWT, "Privileged Admin JWT Token", SeverityHigh, ConfidenceHigh
	}

	return true, SecretJWT, "JSON Web Token (JWT)", SeverityMedium, ConfidenceMedium
}

// decodeBase64URL safely decodes base64url data with or without padding.
func decodeBase64URL(input string) ([]byte, error) {
	// Try raw URL decoding first
	data, err := base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return data, nil
	}

	// Add missing padding if needed
	pad := len(input) % 4
	if pad > 0 {
		input += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(input)
}
