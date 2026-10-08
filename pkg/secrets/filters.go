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

	// 8. Filter structured alphabet and character-set lookup tables
	if isStructuredAlphabet(clean, surroundingContext) {
		return true
	}

	return false
}

var knownEncodingAlphabets = []string{
	// Standard Base64
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	// Base64URL / nanoid default
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
	// Reversed Base64URL
	"-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	// Base62 variants
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	// Base36
	"0123456789abcdefghijklmnopqrstuvwxyz",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	// Base32 (RFC 4648)
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
	// Base32 (Crockford)
	"0123456789ABCDEFGHJKMNPQRSTVWXYZ",
	// Base58 (Bitcoin)
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
	// Base58 (Flickr)
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
	// Hexadecimal lookup
	"0123456789abcdef",
	"0123456789ABCDEF",
	"0123456789abcdefABCDEF",
}

// IsStructuredAlphabet evaluates whether a string represents a character-set or encoding lookup table
// rather than a random high-entropy credential.
func IsStructuredAlphabet(candidate, surroundingContext string) bool {
	return isStructuredAlphabet(candidate, surroundingContext)
}

func isStructuredAlphabet(candidate, surroundingContext string) bool {
	clean := strings.TrimSpace(candidate)
	if len(clean) < 16 {
		return false
	}

	// 1. Direct match or substring containment of standard encoding alphabets
	for _, alpha := range knownEncodingAlphabets {
		if clean == alpha || strings.Contains(clean, alpha) {
			return true
		}
	}

	// 2. Full alphabetical range check
	// If a candidate contains the complete 26-letter uppercase or lowercase English alphabet
	// in ascending order, it is an alphabet lookup table rather than a random secret.
	if strings.Contains(clean, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || strings.Contains(clean, "abcdefghijklmnopqrstuvwxyz") {
		return true
	}

	// 3. Structural character uniqueness and sequential runs analysis:
	// Encoding tables are bijective sets of distinct characters organized in sequential blocks.
	seen := make(map[rune]struct{}, len(clean))
	duplicates := 0
	for _, r := range clean {
		if _, exists := seen[r]; exists {
			duplicates++
		} else {
			seen[r] = struct{}{}
		}
	}

	// In an alphabet table, almost all characters are unique (allowing at most 2 duplicates for edge padding)
	if duplicates > 2 {
		return false
	}

	// Measure contiguous ascending ASCII runs (where clean[i] == clean[i-1] + 1)
	runLength := 1
	totalSequentialChars := 0
	hasSignificantRun := false

	for i := 1; i < len(clean); i++ {
		if clean[i] == clean[i-1]+1 {
			runLength++
		} else {
			if runLength >= 4 {
				totalSequentialChars += runLength
				if runLength >= 6 {
					hasSignificantRun = true
				}
			}
			runLength = 1
		}
	}
	if runLength >= 4 {
		totalSequentialChars += runLength
		if runLength >= 6 {
			hasSignificantRun = true
		}
	}

	// If sequential runs of length >= 4 account for at least 60% of the entire string,
	// it is a structured sequential character table.
	if hasSignificantRun && float64(totalSequentialChars)/float64(len(clean)) >= 0.60 {
		return true
	}

	// 4. Context corroboration:
	// If context explicitly references an alphabet/charset and the string has sequential runs
	lowerCtx := strings.ToLower(surroundingContext)
	if strings.Contains(lowerCtx, "alphabet") || strings.Contains(lowerCtx, "charset") ||
		strings.Contains(lowerCtx, "customalphabet") || strings.Contains(lowerCtx, "dictionary") {
		if totalSequentialChars >= 8 || strings.Contains(clean, "0123456789") {
			return true
		}
	}

	return false
}
