package secrets

import (
	"regexp"
	"strings"
)

var (
	uuidRegex   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRegex    = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	cssValRegex = regexp.MustCompile(`^(?:rgba?\(|hsla?\(|#[0-9a-fA-F]{3,8}|var\(--)`)
)

var exactPlaceholders = []string{
	"example",
	"example-key",
	"example_key",
	"test-key",
	"test_key",
	"dummy",
	"placeholder",
	"your_api_key",
	"your_secret",
	"replace_me",
	"change_me",
	"todo",
	"fixme",
	"null",
	"undefined",
}

var substringPlaceholders = []string{
	"your_api_key",
	"your_secret",
	"your_token",
	"your-api-key",
	"your-secret",
	"yourapikey",
	"yoursecret",
	"replace_me",
	"replace-me",
	"replaceme",
	"change_me",
	"change-me",
	"changeme",
	"insert_key",
	"enter_key",
	"example_key",
	"example-key",
	"test_key",
	"test-key",
	"dummy",
	"placeholder",
	"fake_key",
	"xxxxxxxxx",
	"0000000000",
}

// IsPlaceholder checks if a candidate string matches standard dummy or tutorial values.
func IsPlaceholder(candidate string) bool {
	lower := strings.ToLower(candidate)

	for _, ep := range exactPlaceholders {
		if lower == ep {
			return true
		}
	}

	for _, sp := range substringPlaceholders {
		if strings.Contains(lower, sp) {
			return true
		}
	}

	return false
}

// IsFalsePositive filters out common non-secret strings such as UUIDs, hashes, and CSS rules.
func IsFalsePositive(candidate string, sType SecretType, surroundingContext string) bool {
	clean := strings.TrimSpace(candidate)
	if len(clean) == 0 {
		return true
	}

	// 1. Check placeholders
	if IsPlaceholder(clean) {
		return true
	}

	// 2. Private keys and recognized provider signatures are not false positives unless they match placeholders
	if sType == SecretPrivateKey || sType == SecretAWSAccessKey || sType == SecretStripeLiveKey ||
		sType == SecretGitHubToken || sType == SecretSlackToken || sType == SecretOpenAIKey ||
		sType == SecretSupabaseServiceKey {
		return false
	}

	// 3. Filter UUIDs
	if uuidRegex.MatchString(clean) {
		return true
	}

	// 4. Filter CSS values
	if cssValRegex.MatchString(clean) {
		return true
	}

	// 5. Filter raw hex hashes (git commit SHA, MD5, SHA256) unless context strongly implies a secret
	if hexRegex.MatchString(clean) {
		lowerCtx := strings.ToLower(surroundingContext)
		hasSecretKeyword := strings.Contains(lowerCtx, "secret") ||
			strings.Contains(lowerCtx, "token") ||
			strings.Contains(lowerCtx, "api_key") ||
			strings.Contains(lowerCtx, "private")
		if !hasSecretKeyword {
			return true
		}
	}

	// 6. Filter webpack identifiers and common build artifacts
	if strings.HasPrefix(clean, "webpackChunk") || strings.Contains(clean, "chunk-") {
		return true
	}

	// 7. Filter source-map base64 data URIs
	if strings.HasPrefix(clean, "data:application/json;base64,") {
		return true
	}

	return false
}
