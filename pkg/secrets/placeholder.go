package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var knownPlaceholderTokens = map[string]string{
	"AKIAIOSFODNN7EXAMPLE":                     "AWS official documentation example AccessKeyId",
	"WJALRXUTNFEMI/K7MDENG/BPXRFIYEXAMPLEKEY":  "AWS documentation example SecretAccessKey typo variant",
	"WJALRXUTNFEMI/K7MDENG/BPXRFICYEXAMPLEKEY": "AWS official documentation example SecretAccessKey",
	"ASIAIOSFODNN7EXAMPLE":                     "AWS official documentation example temporary AccessKeyId",
}

var placeholderSubstrings = []struct {
	needle string
	reason string
}{
	{"AKIAIOSFODNN7EXAMPLE", "AWS documentation example key AKIAIOSFODNN7EXAMPLE"},
	{"WPXRFIICYEXAMPLEKEY", "AWS documentation example secret key"},
	{"BPXRFICYEXAMPLEKEY", "AWS documentation example secret key"},
	{"EXAMPLEKEY", "Example key suffix marker"},
	{"EXAMPLE_KEY", "Example key placeholder marker"},
	{"EXAMPLE_TOKEN", "Example token placeholder marker"},
	{"EXAMPLE_SECRET", "Example secret placeholder marker"},
	{"PLACEHOLDER", "Explicit placeholder marker"},
	{"YOUR_API_KEY", "Template API key placeholder"},
	{"YOUR-API-KEY", "Template API key placeholder"},
	{"YOUR_ACCESS_TOKEN", "Template access token placeholder"},
	{"YOUR_TOKEN", "Template token placeholder"},
	{"YOUR_SECRET", "Template secret placeholder"},
	{"INSERT_YOUR_", "Template credential placeholder"},
	{"REPLACE_ME", "Template replacement placeholder"},
	{"CHANGEME", "Default password placeholder"},
	{"DUMMY_KEY", "Dummy key placeholder"},
	{"DUMMY_TOKEN", "Dummy token placeholder"},
	{"FAKE_KEY", "Fake key placeholder"},
	{"FAKE_TOKEN", "Fake token placeholder"},
	{"SAMPLE_KEY", "Sample key placeholder"},
	{"SAMPLE_TOKEN", "Sample token placeholder"},
	{"NOT_A_REAL_", "Non-credential synthetic marker"},
	{"INVALID_PLACEHOLDER", "Explicit invalid placeholder credential"},
}

var awsKeyExampleSuffixRe = regexp.MustCompile(`(?i)\b(?:AKIA|ASIA|AROA)[A-Z0-9]{12,}EXAMPLE\b`)
var prefixedPlaceholderTokenRe = regexp.MustCompile(`(?i)\b(?:ghp|gho|ghu|ghs|ghr|sk_live|sk_test|pk_live|xox[baprs]|AIza)[A-Za-z0-9_\-]*example[A-Za-z0-9_\-]*\b`)
var repeatedCharTokenRe = regexp.MustCompile(`^(?:x{8,}|0{8,}|a{8,}|\*{6,})$`)

// IsKnownPlaceholderCredential checks whether a token or credential-shaped string is a
// documentation example, template value, or synthetic placeholder rather than a usable secret.
func IsKnownPlaceholderCredential(val string) (bool, string) {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return false, ""
	}
	upper := strings.ToUpper(trimmed)

	if reason, ok := knownPlaceholderTokens[upper]; ok {
		return true, reason
	}
	if awsKeyExampleSuffixRe.MatchString(trimmed) {
		return true, "AWS access key pattern ends with documentation EXAMPLE suffix"
	}
	if prefixedPlaceholderTokenRe.MatchString(trimmed) {
		return true, "Prefixed token contains example placeholder marker"
	}
	if repeatedCharTokenRe.MatchString(strings.ToLower(trimmed)) {
		return true, "Repeated dummy filler character pattern"
	}
	if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && len(trimmed) < 64 {
		return true, "Angle-bracketed template placeholder"
	}

	for _, entry := range placeholderSubstrings {
		if strings.Contains(upper, entry.needle) {
			return true, entry.reason
		}
	}
	return false, ""
}

// ContainsPlaceholderCredential reports whether arbitrary evidence or text contains a known
// placeholder or documentation example credential.
func ContainsPlaceholderCredential(text string) (bool, string) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return false, ""
	}
	if ok, reason := IsKnownPlaceholderCredential(trimmed); ok {
		return true, reason
	}
	// Scan whitespace/punctuation separated tokens cleanly
	fields := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r <= ' ' || r == '"' || r == '\'' || r == ',' || r == ';' || r == '(' || r == ')' || r == '=' || r == ':'
	})
	for _, tok := range fields {
		if ok, reason := IsKnownPlaceholderCredential(tok); ok {
			return true, reason
		}
	}
	return false, ""
}

// CredentialFingerprint returns a non-reversible SHA-256 prefix fingerprint for a secret
// so relationships and logs can identify credentials safely without exposing raw tokens.
func CredentialFingerprint(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
