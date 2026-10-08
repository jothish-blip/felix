package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SecretType categorizes the specific kind of detected secret or credential.
type SecretType string

const (
	SecretAWSAccessKey       SecretType = "aws-access-key"
	SecretAWSSecretKey       SecretType = "aws-secret-key"
	SecretStripeLiveKey      SecretType = "stripe-live-key"
	SecretGitHubToken        SecretType = "github-token"
	SecretSlackToken         SecretType = "slack-token"
	SecretOpenAIKey          SecretType = "openai-key"
	SecretJWT                SecretType = "jwt"
	SecretPrivateKey         SecretType = "private-key"
	SecretSupabaseServiceKey SecretType = "supabase-service-key"
	SecretHighEntropy        SecretType = "high-entropy"
)

// Severity and Confidence ratings for secret findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"

	ConfidenceHigh   = "High"
	ConfidenceMedium = "Medium"
	ConfidenceLow    = "Low"
)

// SecretFinding represents a discovered security-sensitive token or key.
type SecretFinding struct {
	Type        SecretType `json:"type"`
	Title       string     `json:"title"`
	Value       string     `json:"-"` // Raw value held internally only for deduplication & validation
	Redacted    string     `json:"redacted_value"`
	FileOrigin  string     `json:"file_origin"`
	LineNumber  int        `json:"line_number"`
	Severity    string     `json:"severity"`
	Confidence  string     `json:"confidence"`
	Evidence    string     `json:"evidence"`
	Fingerprint string     `json:"fingerprint"`
}

// GenerateFingerprint creates a secure SHA-256 fingerprint for finding deduplication.
// It never exposes the raw secret in plain text.
func GenerateFingerprint(sType SecretType, value string) string {
	h := sha256.New()
	h.Write([]byte(string(sType) + ":" + strings.TrimSpace(value)))
	return hex.EncodeToString(h.Sum(nil))
}

// RedactSecret produces a safe masked representation of sensitive credentials.
// It ensures that full credentials are never exposed in terminal outputs or logs.
func RedactSecret(val string) string {
	clean := strings.TrimSpace(val)
	if len(clean) == 0 {
		return ""
	}

	// 1. Private keys
	if strings.Contains(clean, "PRIVATE KEY") {
		startTag := "-----BEGIN"
		if idx := strings.Index(clean, startTag); idx != -1 {
			endHeader := strings.Index(clean[idx:], "-----")
			if endHeader != -1 && idx+endHeader+5 <= len(clean) {
				sub := clean[idx : idx+endHeader+5]
				// Look for second line or end of header
				lines := strings.Split(clean, "\n")
				if len(lines) > 0 {
					return lines[0] + "... [REDACTED PRIVATE KEY] ..."
				}
				return sub + "... [REDACTED PRIVATE KEY] ..."
			}
		}
		return "-----BEGIN [REDACTED PRIVATE KEY] -----"
	}

	// 2. JWT tokens: header.payload.signature
	parts := strings.Split(clean, ".")
	if len(parts) == 3 {
		h := parts[0]
		if len(h) > 8 {
			h = h[:8] + "..."
		}
		return h + ".********************.[REDACTED_SIG]"
	}

	// 3. Known prefixes
	prefixes := []string{"sk_live_", "rk_live_", "ghp_", "xoxb-", "sk-proj-", "sk-", "AKIA"}
	for _, p := range prefixes {
		if strings.HasPrefix(clean, p) {
			suffixLen := 4
			if len(clean) <= len(p)+suffixLen {
				return p + strings.Repeat("*", len(clean)-len(p))
			}
			suffix := clean[len(clean)-suffixLen:]
			return p + strings.Repeat("*", 20) + suffix
		}
	}

	// 4. General strings: keep first 4 and last 4 if length >= 12
	if len(clean) >= 12 {
		prefix := clean[:4]
		suffix := clean[len(clean)-4:]
		return prefix + strings.Repeat("*", 16) + suffix
	}

	// 5. Short strings: completely mask with asterisks
	return strings.Repeat("*", len(clean))
}
