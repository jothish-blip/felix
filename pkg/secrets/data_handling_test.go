package secrets_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"felix/pkg/config"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Synthetic Canary Secrets for Data Handling and Serialization Leak Verification.
// These are synthetic test strings that must NEVER leak into exported artifacts.
const (
	canaryGitHubToken = "ghp_" + "CANARYTESTTOKEN1234567890abcdef"
	canaryAWSKey      = "AKIA" + "IOSFODNN7CANARY01"
	canaryStripeKey   = "sk_live_" + "CANARYSTRIPESECRET1234567890"
	canaryPassword    = "CANARY_PASSWORD_SUPER_SECRET_XYZ999!"
	canaryBearer      = "CANARY_BEARER_AUTH_TOKEN_ABC123"
	canaryPEMKey      = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCANARYTESTPRIVATEKEYDATA\n-----END " + "PRIVATE KEY-----"
)

var canaryTokens = []string{
	canaryGitHubToken,
	canaryAWSKey,
	canaryStripeKey,
	canaryPassword,
	canaryBearer,
	"CANARYTESTPRIVATEKEYDATA",
}

// assertCleanOutput verifies that none of the synthetic canaries appear in the output string.
func assertCleanOutput(t *testing.T, output, outputFormat string) {
	t.Helper()
	for _, c := range canaryTokens {
		if strings.Contains(output, c) {
			t.Fatalf("LEAK DETECTED in %s output: synthetic canary %q leaked into exported document", outputFormat, c)
		}
	}
}

// TestDataHandling_FinalSerializedReports verifies that raw sensitive tokens, credentials,
// and private keys never leak into final JSON, HTML, or SARIF serialized reports.
func TestDataHandling_FinalSerializedReports(t *testing.T) {
	// 1. Build a Report populated with synthetic canaries across all supported fields
	rep := report.Report{
		Version: "2.0.0",
		Target:  fmt.Sprintf("https://canaryuser:%s@example.com/app?token=%s&key=%s", canaryPassword, canaryGitHubToken, canaryAWSKey),
		Targets: []string{
			fmt.Sprintf("https://canaryuser:%s@example.com/app", canaryPassword),
		},
		Findings: []report.Finding{
			{
				ID:          "fnd-01",
				RuleID:      "SEC-AWS-KEY",
				Category:    "SECRETS",
				Title:       fmt.Sprintf("Exposed AWS Key: %s in main.js", canaryAWSKey),
				Description: fmt.Sprintf("Found AWS key %s alongside bearer %s and password: %s", canaryAWSKey, canaryBearer, canaryPassword),
				Severity:    report.SeverityCritical,
				Confidence:  report.ConfidenceHigh,
				Target:      "https://example.com/app",
				Endpoint:    fmt.Sprintf("https://example.com/api?token=%s&stripe=%s", canaryGitHubToken, canaryStripeKey),
				Evidence:    fmt.Sprintf("const key = '%s';\nconst secret = '%s';\nconst password = '%s';\n%s", canaryAWSKey, canaryStripeKey, canaryPassword, canaryPEMKey),
				Remediation: fmt.Sprintf("Revoke key %s and reset password=%s immediately.", canaryAWSKey, canaryPassword),
				EvidenceDetails: report.EvidenceDetails{
					Observation: fmt.Sprintf("Observation leaked password: %s and token: %s", canaryPassword, canaryGitHubToken),
					Location:    fmt.Sprintf("https://example.com/login?pwd=%s", canaryPassword),
					Details: map[string]string{
						"client_secret": canaryPassword,
						"api_key":       canaryStripeKey,
						"auth_token":    canaryBearer,
						"raw_snippet":   fmt.Sprintf("Bearer %s", canaryBearer),
					},
				},
				Verification: report.VerificationRecord{
					Status:          report.VerificationVerified,
					Result:          fmt.Sprintf("Verified using %s", canaryAWSKey),
					Rationale:       fmt.Sprintf("Confirmed with token %s", canaryGitHubToken),
					SafeCurlCommand: fmt.Sprintf("curl -H 'Authorization: Bearer %s' -H 'X-Api-Key: %s' https://example.com", canaryBearer, canaryStripeKey),
					ReproductionSteps: []string{
						fmt.Sprintf("Send request with Authorization: Bearer %s", canaryBearer),
						fmt.Sprintf("Verify response containing key=%s", canaryAWSKey),
					},
				},
			},
		},
		SecurityStories: []report.SecurityStory{
			{
				ID:          "story-01",
				Title:       fmt.Sprintf("Story Leaking token=%s", canaryGitHubToken),
				Summary:     fmt.Sprintf("Summary containing api_key: %s", canaryGitHubToken),
				Description: fmt.Sprintf("Description containing password: %s and %s", canaryPassword, canaryStripeKey),
				Evidence: []string{
					fmt.Sprintf("Evidence Authorization: Bearer %s", canaryBearer),
				},
			},
		},
		AttackPaths: []report.AttackPathSummary{
			{
				ID:            "path-01",
				Title:         fmt.Sprintf("Attack Path with key=%s", canaryAWSKey),
				RiskRationale: fmt.Sprintf("Risk with password: %s", canaryPassword),
				Remediation:   fmt.Sprintf("Remediate token: %s", canaryGitHubToken),
				Transitions: []string{
					fmt.Sprintf("Step 1: Use key=%s", canaryAWSKey),
				},
			},
		},
	}

	// 2. Test JSON Serialization
	jsonBytes, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)
	assertCleanOutput(t, jsonStr, "JSON")

	// Positive assertion: Redaction placeholders must be present
	if !strings.Contains(jsonStr, "[REDACTED") {
		t.Errorf("expected [REDACTED placeholder in JSON output")
	}

	// 3. Test HTML Serialization
	htmlStr, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	assertCleanOutput(t, htmlStr, "HTML")

	// Positive assertion: Redaction placeholders present in HTML
	if !strings.Contains(htmlStr, "[REDACTED") {
		t.Errorf("expected [REDACTED placeholder in HTML output")
	}

	// 4. Test SARIF Serialization
	sarifLog := report.BuildSARIFLog(rep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("SARIF Marshal failed: %v", err)
	}
	sarifStr := string(sarifBytes)
	assertCleanOutput(t, sarifStr, "SARIF")

	// Positive assertion: Redaction placeholders present in SARIF
	if !strings.Contains(sarifStr, "[REDACTED") {
		t.Errorf("expected [REDACTED placeholder in SARIF output")
	}
}

// TestDataHandling_DiagnosticAndConfigErrorRedaction verifies that error messages,
// diagnostic outputs, and configuration validation errors never reflect raw secrets.
func TestDataHandling_DiagnosticAndConfigErrorRedaction(t *testing.T) {
	// 1. Unknown config key containing secret
	cfg := config.Default()
	_, err := cfg.Get("secret_key_" + canaryGitHubToken)
	if err == nil {
		t.Fatalf("expected error for unknown key")
	}
	if strings.Contains(err.Error(), canaryGitHubToken) {
		t.Fatalf("LEAK: raw canary secret reflected in cfg.Get error: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected redacted placeholder in cfg.Get error: %v", err)
	}

	// 2. cfg.Set with sensitive unknown key
	err = cfg.Set("api_key_"+canaryAWSKey, "val")
	if err == nil {
		t.Fatalf("expected error for unknown key in cfg.Set")
	}
	if strings.Contains(err.Error(), canaryAWSKey) {
		t.Fatalf("LEAK: raw canary secret reflected in cfg.Set error: %v", err)
	}

	// 3. Invalid scope containing secret value
	cfg.Scope = "invalid_scope_" + canaryGitHubToken
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid scope")
	}
	if strings.Contains(err.Error(), canaryGitHubToken) {
		t.Fatalf("LEAK: raw canary secret reflected in cfg.Validate scope error: %v", err)
	}

	cfg.Scope = "scope_password=" + canaryPassword
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid scope")
	}
	if strings.Contains(err.Error(), canaryPassword) {
		t.Fatalf("LEAK: raw canary password reflected in cfg.Validate scope error: %v", err)
	}

	// 4. RedactText direct sanity check
	rawText := fmt.Sprintf("Error connecting with user:pass auth: https://admin:%s@db.internal:5432/db", canaryPassword)
	sanitized := secrets.RedactText(rawText)
	if strings.Contains(sanitized, canaryPassword) {
		t.Fatalf("LEAK: raw password in RedactText output: %s", sanitized)
	}
}
