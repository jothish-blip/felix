package secrets

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"

	"felix/pkg/crawler"
)

// Helper to create valid unverified test JWT tokens
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature-data-bytes-here-123456"))
	return header + "." + payload + "." + signature
}

// Test 1: AWS access key detection
func TestAWSAccessKeyDetection(t *testing.T) {
	d := NewDetector()
	js := `
		// Configuration file
		const AWS_REGION = "us-east-1";
		const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
	`

	findings := d.ScanContent("config.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected AWS access key finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretAWSAccessKey {
		t.Errorf("expected %s, got %s", SecretAWSAccessKey, f.Type)
	}
	if f.Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected AKIAIOSFODNN7EXAMPLE, got %s", f.Value)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected High confidence, got %s", f.Confidence)
	}
}

// Test 2: Stripe secret detection
func TestStripeSecretDetection(t *testing.T) {
	d := NewDetector()
	js := `
		const stripe = require('stripe')('sk_live_51Abcdef1234567890abcdef1234567890');
		const publicStripe = 'pk_live_51Abcdef1234567890abcdef1234567890';
	`

	findings := d.ScanContent("checkout.js", []byte(js))
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 Stripe live secret finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != SecretStripeLiveKey {
		t.Errorf("expected %s, got %s", SecretStripeLiveKey, f.Type)
	}
	if f.Value != "sk_live_51Abcdef1234567890abcdef1234567890" {
		t.Errorf("unexpected value: %s", f.Value)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

// Test 3: GitHub token detection
func TestGitHubTokenDetection(t *testing.T) {
	d := NewDetector()
	js := `
		export const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
	`

	findings := d.ScanContent("api.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected GitHub token finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretGitHubToken {
		t.Errorf("expected %s, got %s", SecretGitHubToken, f.Type)
	}
	if f.Value != "ghp_1234567890abcdefghijklmnopqrstuvwxyz" {
		t.Errorf("unexpected value: %s", f.Value)
	}
}

// Test 4: Slack token detection
func TestSlackTokenDetection(t *testing.T) {
	d := NewDetector()
	js := `
		const botToken = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";
	`

	findings := d.ScanContent("slack.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected Slack bot token finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretSlackToken {
		t.Errorf("expected %s, got %s", SecretSlackToken, f.Type)
	}
	if f.Value != "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx" {
		t.Errorf("unexpected value: %s", f.Value)
	}
}

// Test 5: OpenAI key detection
func TestOpenAIKeyDetection(t *testing.T) {
	d := NewDetector()
	js := `
		const openaiKey = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef";
	`

	findings := d.ScanContent("ai.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected OpenAI key finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretOpenAIKey {
		t.Errorf("expected %s, got %s", SecretOpenAIKey, f.Type)
	}
	if f.Value != "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef" {
		t.Errorf("unexpected value: %s", f.Value)
	}
}

// Test 6: JWT detection
func TestJWTDetection(t *testing.T) {
	d := NewDetector()
	token := createTestJWT(map[string]interface{}{
		"sub":  "1234567890",
		"name": "Felix Auditor",
		"iat":  1516239022,
	})

	js := `const authToken = "` + token + `";`
	findings := d.ScanContent("auth.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected JWT finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretJWT {
		t.Errorf("expected %s, got %s", SecretJWT, f.Type)
	}
}

// Test 7: Private-key detection
func TestPrivateKeyDetection(t *testing.T) {
	d := NewDetector()
	privKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3w8...fake...content...
...more...lines...
-----END RSA PRIVATE KEY-----`

	js := `const serverKey = ` + "`" + privKey + "`" + `;`

	findings := d.ScanContent("server.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected private key finding, got 0")
	}

	f := findings[0]
	if f.Type != SecretPrivateKey {
		t.Errorf("expected %s, got %s", SecretPrivateKey, f.Type)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
}

// Test 8: Supabase anon key is NOT automatically classified as a privileged secret
func TestSupabaseAnonKeyNotPrivileged(t *testing.T) {
	d := NewDetector()
	anonToken := createTestJWT(map[string]interface{}{
		"iss":  "supabase",
		"ref":  "my-project",
		"role": "anon",
		"exp":  1893456000,
	})

	js := `
		import { createClient } from '@supabase/supabase-js'
		const supabaseUrl = 'https://xyzcompany.supabase.co'
		const supabaseAnonKey = '` + anonToken + `'
		export const supabase = createClient(supabaseUrl, supabaseAnonKey)
	`

	findings := d.ScanContent("supabaseClient.js", []byte(js))
	for _, f := range findings {
		if f.Type == SecretSupabaseServiceKey {
			t.Errorf("Supabase anon key must NOT be classified as service_role secret: %+v", f)
		}
		if f.Severity == SeverityCritical {
			t.Errorf("Supabase anon key must not be critical severity: %+v", f)
		}
	}
}

// Test 9: Supabase service-role credential is detected appropriately
func TestSupabaseServiceRoleDetection(t *testing.T) {
	d := NewDetector()
	serviceRoleToken := createTestJWT(map[string]interface{}{
		"iss":  "supabase",
		"ref":  "my-project",
		"role": "service_role",
		"exp":  1893456000,
	})

	js := `
		// Leaked backend admin client in frontend bundle
		const adminKey = "` + serviceRoleToken + `";
	`

	findings := d.ScanContent("admin.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected Supabase service_role key finding, got 0")
	}

	var found bool
	for _, f := range findings {
		if f.Type == SecretSupabaseServiceKey && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SecretSupabaseServiceKey with CRITICAL severity, got: %+v", findings)
	}
}

// Test 10: Entropy calculation
func TestShannonEntropy(t *testing.T) {
	// 1. Empty string
	if e := ShannonEntropy(""); e != 0.0 {
		t.Errorf("expected 0.0 for empty string, got %f", e)
	}

	// 2. Uniform repeated characters
	if e := ShannonEntropy("aaaaaaaa"); e != 0.0 {
		t.Errorf("expected 0.0 for repeated characters, got %f", e)
	}

	// 3. Short string with 2 distinct chars (each prob 0.5 -> 1.0 bit)
	if e := ShannonEntropy("ab"); math.Abs(e-1.0) > 0.001 {
		t.Errorf("expected ~1.0 for 'ab', got %f", e)
	}

	// 4. Normal English text (~3.0 to 4.2 bits)
	english := "The quick brown fox jumps over the lazy dog"
	engEntropy := ShannonEntropy(english)
	if engEntropy < 3.0 || engEntropy > 4.5 {
		t.Errorf("expected English text entropy between 3.0 and 4.5, got %f", engEntropy)
	}

	// 5. Random high-entropy base64 string (> 4.5 bits)
	randomToken := "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z="
	randEntropy := ShannonEntropy(randomToken)
	if randEntropy < 4.5 {
		t.Errorf("expected random string entropy > 4.5, got %f", randEntropy)
	}
}

// Test 11: Placeholder filtering
func TestPlaceholderFiltering(t *testing.T) {
	d := NewDetector()
	js := `
		const awsKey = "AKIAYOURAPIKEYHERE12";
		const stripeKey = "sk_live_YOUR_SECRET_KEY_REPLACE_ME_NOW";
		const token = "ghp_EXAMPLE_KEY_DUMMY_PLACEHOLDER_123456";
	`

	findings := d.ScanContent("test.js", []byte(js))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for obvious placeholders, got %d: %+v", len(findings), findings)
	}
}

// Test 12: Context-based confidence
func TestContextBasedConfidence(t *testing.T) {
	d := NewDetector()

	// High context: sensitive variable name
	jsWithContext := `const stripe_secret_key = "sk_live_51Abcdef1234567890abcdef1234567890";`
	findingsContext := d.ScanContent("app.js", []byte(jsWithContext))
	if len(findingsContext) == 0 {
		t.Fatalf("expected finding with context")
	}
	if findingsContext[0].Confidence != ConfidenceHigh {
		t.Errorf("expected High confidence when secret context keywords present, got %s", findingsContext[0].Confidence)
	}
}

// Test 13: Line-number detection
func TestLineNumberDetection(t *testing.T) {
	d := NewDetector()
	js := `// Line 1
// Line 2
// Line 3
// Line 4
const AWS_ACCESS = "AKIA1234567890ABCDEF"; // Line 5
// Line 6
`

	findings := d.ScanContent("app.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected finding, got 0")
	}
	if findings[0].LineNumber != 5 {
		t.Errorf("expected line number 5, got %d", findings[0].LineNumber)
	}
}

// Test 14: Duplicate finding suppression
func TestDuplicateFindingSuppression(t *testing.T) {
	d := NewDetector()

	asset1 := crawler.Asset{
		URL:     "https://example.com/app.js",
		Type:    crawler.AssetJavaScript,
		Content: []byte(`const key = "AKIA1234567890ABCDEF";`),
	}
	asset2 := crawler.Asset{
		URL:     "https://example.com/vendor.js",
		Type:    crawler.AssetJavaScript,
		Content: []byte(`const sharedKey = "AKIA1234567890ABCDEF";`),
	}

	findings := d.ScanAssets([]crawler.Asset{asset1, asset2})
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 deduplicated finding across assets, got %d", len(findings))
	}
}

// Test 15: Secret redaction
func TestSecretRedaction(t *testing.T) {
	rawStripe := "sk_live_51Abcdef1234567890abcdef1234567890"
	redactedStripe := RedactSecret(rawStripe)

	if strings.Contains(redactedStripe, "51Abcdef1234567890abcdef") {
		t.Errorf("redacted value must NOT expose middle secret body: %s", redactedStripe)
	}
	if !strings.HasPrefix(redactedStripe, "sk_live_") {
		t.Errorf("redacted value should keep prefix: %s", redactedStripe)
	}
	if !strings.HasSuffix(redactedStripe, "7890") {
		t.Errorf("redacted value should keep last 4 chars: %s", redactedStripe)
	}

	// Test private key redaction
	rawPriv := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	redactedPriv := RedactSecret(rawPriv)
	if strings.Contains(redactedPriv, "MIIEow") {
		t.Errorf("redacted private key must not leak key payload: %s", redactedPriv)
	}
}

// Test 16: Source-map sourcesContent analysis
func TestSourceMapSourcesContentAnalysis(t *testing.T) {
	d := NewDetector()

	smPayload := map[string]interface{}{
		"version": 3,
		"sources": []string{"webpack:///src/config/keys.ts", "webpack:///src/index.ts"},
		"sourcesContent": []string{
			"// Original TypeScript source\nexport const STRIPE_LIVE_KEY = 'sk_live_51Abcdef1234567890abcdef1234567890';\n",
			"console.log('App started');",
		},
	}
	smBytes, _ := json.Marshal(smPayload)

	smAsset := crawler.Asset{
		URL:         "https://example.com/static/js/app.js.map",
		Type:        crawler.AssetSourceMap,
		IsSourceMap: true,
		Content:     smBytes,
	}

	findings := d.ScanAssets([]crawler.Asset{smAsset})
	if len(findings) == 0 {
		t.Fatalf("expected finding from source map sourcesContent, got 0")
	}

	f := findings[0]
	if f.Type != SecretStripeLiveKey {
		t.Errorf("expected %s, got %s", SecretStripeLiveKey, f.Type)
	}
	if f.FileOrigin != "webpack:///src/config/keys.ts" {
		t.Errorf("expected FileOrigin webpack:///src/config/keys.ts, got %s", f.FileOrigin)
	}
	if f.LineNumber != 2 {
		t.Errorf("expected LineNumber 2 in original source, got %d", f.LineNumber)
	}
}

// Test 17: Normal JavaScript does not produce excessive false positives
func TestNormalJavaScriptFalsePositives(t *testing.T) {
	d := NewDetector()

	// Realistic typical minified library snippet (jQuery / React-like)
	benignJS := `
		!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e="undefined"!=typeof globalThis?globalThis:e||self).App=t()}(this,(function(){"use strict";
		var r={a:"rgba(255,255,255,0.8)",uuid:"123e4567-e89b-12d3-a456-426614174000",hash:"5f4dcc3b5aa765d61d8327deb882cf99",chunk:"webpackChunk_bundle"};
		function init(e){return r.a+e}
		return{init:init}
		}));
	`

	findings := d.ScanContent("bundle.min.js", []byte(benignJS))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for normal JavaScript, got %d: %+v", len(findings), findings)
	}
}

// Test Concurrent Detector Safety
func TestConcurrentDetectorSafety(t *testing.T) {
	d := NewDetector()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			js := `const key = "AKIA1234567890ABCDEF"; const stripe = "sk_live_51Abcdef1234567890abcdef1234567890";`
			findings := d.ScanContent("worker.js", []byte(js))
			if len(findings) < 2 {
				t.Errorf("expected at least 2 findings in worker goroutine %d, got %d", id, len(findings))
			}
		}(i)
	}
	wg.Wait()
}

// Test 19: Isolated unit test for structured alphabet filtering
func TestStructuredAlphabetFilter(t *testing.T) {
	knownCases := []struct {
		name     string
		input    string
		context  string
		expected bool
	}{
		{
			name:     "NexSpace Base64URL/nanoid alphabet table",
			input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
			context:  "const urlAlphabet = ...",
			expected: true,
		},
		{
			name:     "Standard RFC 4648 Base64 alphabet table",
			input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
			context:  "var b64 = ...",
			expected: true,
		},
		{
			name:     "Base62 alphanumeric charset table",
			input:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
			context:  "const base62Chars = ...",
			expected: true,
		},
		{
			name:     "Hexadecimal lookup alphabet",
			input:    "0123456789abcdef",
			context:  "const hexDigits = ...",
			expected: true,
		},
		{
			name:     "Bitcoin Base58 character lookup table",
			input:    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
			context:  "const b58 = ...",
			expected: true,
		},
		{
			name:     "Custom nanoid alphabet with context keyword",
			input:    "use-random-values-0123456789abcdefghijklmnopqrstuvwxyz",
			context:  "customAlphabet(alphabet, 21)",
			expected: true,
		},
		{
			name:     "Cryptographic base64 token",
			input:    "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=",
			context:  "const api_key = ...",
			expected: false,
		},
		{
			name:     "Random high-entropy API secret string",
			input:    "dGhpc0lzQVZlcnlIaWdoRW50cm9weVN0cmluZzEyMzQ1Njc4OTA=",
			context:  "const app_secret = ...",
			expected: false,
		},
		{
			name:     "High-entropy pseudo-random hex token",
			input:    "8f7b2c1e4a9d0f3b5e8c1a7d2e4f0a9b",
			context:  "const auth_token = ...",
			expected: false,
		},
		{
			name:     "Stripe live secret key",
			input:    "sk_live_51Abcdef1234567890abcdef1234567890",
			context:  "const stripe_key = ...",
			expected: false,
		},
	}

	for _, tc := range knownCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsStructuredAlphabet(tc.input, tc.context)
			if got != tc.expected {
				t.Errorf("IsStructuredAlphabet(%q, %q) = %v; want %v", tc.input, tc.context, got, tc.expected)
			}
		})
	}
}

// Test 20: Regression test — Alphabet lookup table does NOT produce an entropy finding (NexSpace bug fix)
func TestAlphabetLookupTableFalsePositiveSuppression(t *testing.T) {
	d := NewDetector()

	js := `
		// Third-party nanoid / websocket dependency
		const defaultAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		function generateKey(size) {
			return customAlphabet(defaultAlphabet, size);
		}
	`

	findings := d.ScanContent("0lcc2ylewy3e9.js", []byte(js))
	for _, f := range findings {
		if f.Type == SecretHighEntropy && strings.Contains(f.Value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("alphabet lookup table was incorrectly flagged as high-entropy secret finding: %+v", f)
		}
	}
}

// Test 21: Regression test — Genuinely random high-entropy token is STILL detected
func TestRandomHighEntropySecretDetection(t *testing.T) {
	d := NewDetector()

	js := `
		// Sensitive server API configuration
		const api_key = "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=";
	`

	findings := d.ScanContent("config.js", []byte(js))
	if len(findings) == 0 {
		t.Fatalf("expected genuine high-entropy token to be detected as SecretHighEntropy, got 0 findings")
	}

	found := false
	for _, f := range findings {
		if f.Type == SecretHighEntropy && f.Value == "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=" {
			found = true
			if f.Severity != SeverityLow {
				t.Errorf("expected LOW severity for generic entropy candidate, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected finding for random token, got: %+v", findings)
	}
}

// Test 22: Regression test — High-entropy value with secret context receives appropriate detection
func TestHighEntropyWithSecretContext(t *testing.T) {
	d := NewDetector()

	testContexts := []struct {
		name string
		js   string
	}{
		{
			name: "API_KEY assignment",
			js:   `const API_KEY = "dGhpc0lzQVZlcnlIaWdoRW50cm9weVN0cmluZzEyMzQ1Njc4OTA=";`,
		},
		{
			name: "SECRET assignment",
			js:   `const APP_SECRET = "dGhpc0lzQVZlcnlIaWdoRW50cm9weVN0cmluZzEyMzQ1Njc4OTA=";`,
		},
		{
			name: "TOKEN assignment",
			js:   `const AUTH_TOKEN = "dGhpc0lzQVZlcnlIaWdoRW50cm9weVN0cmluZzEyMzQ1Njc4OTA=";`,
		},
		{
			name: "PASSWORD assignment",
			js:   `const DB_PASSWORD = "dGhpc0lzQVZlcnlIaWdoRW50cm9weVN0cmluZzEyMzQ1Njc4OTA=";`,
		},
	}

	for _, tc := range testContexts {
		t.Run(tc.name, func(t *testing.T) {
			findings := d.ScanContent("test.js", []byte(tc.js))
			if len(findings) == 0 {
				t.Fatalf("expected finding for %s, got 0", tc.name)
			}
			f := findings[0]
			if f.Type != SecretHighEntropy {
				t.Errorf("expected SecretHighEntropy, got %s", f.Type)
			}
		})
	}
}

