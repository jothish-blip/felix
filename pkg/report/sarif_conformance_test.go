package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Scenario 1: Empty findings produces a valid SARIF 2.1.0 document.
func TestSARIF_Conformance_1_EmptyFindings(t *testing.T) {
	rep := Report{
		Target:   "https://example.com",
		Findings: []Finding{},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("validation failed for empty findings: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarifLog.Runs))
	}
	if len(sarifLog.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarifLog.Runs[0].Results))
	}
	if len(sarifLog.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(sarifLog.Runs[0].Tool.Driver.Rules))
	}
}

// Scenario 2: One finding for each supported severity.
func TestSARIF_Conformance_2_AllSupportedSeverities(t *testing.T) {
	severities := []struct {
		felixSev      string
		expectedLevel string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "note"},
		{SeverityInfo, "none"},
		{"UNKNOWN", "none"},
	}

	var findings []Finding
	for idx, s := range severities {
		findings = append(findings, Finding{
			ID:          strings.ToLower(s.felixSev) + "-finding",
			Title:       "Test finding " + s.felixSev,
			Category:    "RULE-" + s.felixSev,
			Severity:    s.felixSev,
			Target:      "https://example.com",
			Endpoint:    "/api/sev/" + strings.ToLower(s.felixSev),
			Fingerprint: "fp-" + strings.ToLower(s.felixSev) + string(rune('0'+idx)),
		})
	}

	rep := Report{
		Target:   "https://example.com",
		Findings: findings,
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("validation failed for all severities: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	results := sarifLog.Runs[0].Results
	if len(results) != len(severities) {
		t.Fatalf("expected %d results, got %d", len(severities), len(results))
	}

	for i, s := range severities {
		if results[i].Level != s.expectedLevel {
			t.Errorf("finding %d (%s): expected level %s, got %s", i, s.felixSev, s.expectedLevel, results[i].Level)
		}
		if results[i].Properties["severity"] != s.felixSev {
			t.Errorf("finding %d (%s): expected preserved raw severity %s, got %v", i, s.felixSev, s.felixSev, results[i].Properties["severity"])
		}
	}
}

// Scenario 3: Multiple rules and findings with stable rule indexing.
func TestSARIF_Conformance_3_MultipleRulesAndFindings(t *testing.T) {
	findings := []Finding{
		{ID: "f1", Category: "XSS", Title: "Reflected XSS", Severity: SeverityHigh, Endpoint: "/search", Fingerprint: "fp-xss-1"},
		{ID: "f2", Category: "SQLI", Title: "Blind SQLi", Severity: SeverityCritical, Endpoint: "/login", Fingerprint: "fp-sqli-1"},
		{ID: "f3", Category: "XSS", Title: "Stored XSS", Severity: SeverityHigh, Endpoint: "/comments", Fingerprint: "fp-xss-2"},
		{ID: "f4", Category: "CORS", Title: "Wildcard CORS", Severity: SeverityMedium, Endpoint: "/data", Fingerprint: "fp-cors-1"},
	}

	rep := Report{
		Target:   "https://example.com",
		Findings: findings,
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	run := sarifLog.Runs[0]
	// Deduplicated rules: CORS, SQLI, XSS (3 rules)
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(run.Results))
	}

	// Verify ruleIndex pointer integrity
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("invalid ruleIndex %d for result %s", res.RuleIndex, res.RuleID)
		}
		referencedRule := run.Tool.Driver.Rules[res.RuleIndex]
		if referencedRule.ID != res.RuleID {
			t.Errorf("mismatched rule reference: result has %q, driver rule at index %d has %q", res.RuleID, res.RuleIndex, referencedRule.ID)
		}
	}
}

// Scenario 4: Missing optional fields and evidence.
func TestSARIF_Conformance_4_MissingOptionalFields(t *testing.T) {
	minimalFinding := Finding{
		ID:          "min-1",
		Title:       "", // empty
		Category:    "", // empty
		Severity:    "", // empty
		Target:      "", // empty
		Endpoint:    "", // empty
		Description: "", // empty
		Evidence:    "", // empty
		Remediation: "", // empty
	}

	rep := Report{
		Findings: []Finding{minimalFinding},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed for minimal finding: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	res := sarifLog.Runs[0].Results[0]
	if res.Message.Text == "" {
		t.Errorf("expected non-empty default message text for minimal finding")
	}
	if len(res.Locations) != 0 {
		t.Errorf("expected 0 locations when target and endpoint are missing, got %d", len(res.Locations))
	}
}

// Scenario 5: Unknown severity handling.
func TestSARIF_Conformance_5_UnknownSeverity(t *testing.T) {
	finding := Finding{
		ID:          "unk-1",
		Category:    "CUSTOM_CHECK",
		Severity:    "UNDEFINED_TIER_99",
		Title:       "Custom observation",
		Endpoint:    "/api/status",
		Fingerprint: "fp-unk-1",
	}

	rep := Report{
		Findings: []Finding{finding},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed for unknown severity: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	res := sarifLog.Runs[0].Results[0]
	if res.Level != "none" {
		t.Errorf("expected level 'none' for unknown severity, got %q", res.Level)
	}
	if res.Properties["severity"] != "UNDEFINED_TIER_99" {
		t.Errorf("expected original severity preserved in properties, got %v", res.Properties["severity"])
	}
}

// Scenario 6: URL-based findings and valid URI handling.
func TestSARIF_Conformance_6_ValidURIHandling(t *testing.T) {
	testCases := []struct {
		name        string
		endpoint    string
		target      string
		expectedURI string
	}{
		{"Absolute URL", "/v1/users", "https://api.example.com", "/v1/users"},
		{"Relative path with query", "/search?q=test&page=1", "https://example.com", "/search?q=test&page=1"},
		{"Spaces in query", "/search?q=hello world", "https://example.com", "/search?q=hello%20world"},
		{"HTTP method prefix in endpoint", "POST /api/v1/auth/login", "https://example.com", "/api/v1/auth/login"},
		{"Windows path with backslashes", `c:\felix\scans\target.html`, "", "c:/felix/scans/target.html"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Report{
				Findings: []Finding{
					{
						ID:          "uri-test",
						Category:    "URI-TEST",
						Severity:    SeverityLow,
						Target:      tc.target,
						Endpoint:    tc.endpoint,
						Fingerprint: "fp-" + tc.name,
					},
				},
			}

			data, err := GenerateSARIF(rep)
			if err != nil {
				t.Fatalf("failed to generate SARIF: %v", err)
			}

			if err := ValidateSARIF(data); err != nil {
				t.Fatalf("schema validation failed for URI case %q: %v", tc.name, err)
			}

			var sarifLog SARIFLog
			_ = json.Unmarshal(data, &sarifLog)

			loc := sarifLog.Runs[0].Results[0].Locations[0]
			if loc.PhysicalLocation.ArtifactLocation.URI != tc.expectedURI {
				t.Errorf("expected URI %q, got %q", tc.expectedURI, loc.PhysicalLocation.ArtifactLocation.URI)
			}
		})
	}
}

// Scenario 7: Special characters, Unicode, newlines, quotes, and backslashes in messages.
func TestSARIF_Conformance_7_SpecialCharactersAndUnicode(t *testing.T) {
	finding := Finding{
		ID:          "unicode-1",
		Category:    "UNICODE_SECURITY",
		Severity:    SeverityHigh,
		Title:       `Injection via "quotes", \backslashes\, and emoji 🚨`,
		Description: "Multi-line description with emoji 🚨:\nLine 1\nLine 2\r\nLine 3\tTabbed\nChinese: 安全漏洞 (Security Vulnerability)",
		Evidence:    `Payload: {"user": "admin' OR '1'='1", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}`,
		Remediation: `Sanitize with regex: ^[a-zA-Z0-9_\-\.\/]+$ and escape " & '`,
		Endpoint:    "/api/unicode/test",
		Fingerprint: "fp-unicode-01",
	}

	rep := Report{
		Findings: []Finding{finding},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed for unicode/special characters: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal JSON with special characters: %v", err)
	}

	msg := sarifLog.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, "安全漏洞") {
		t.Errorf("expected Chinese characters preserved in message, got %s", msg)
	}
	if !strings.Contains(msg, "🚨") {
		t.Errorf("expected emoji preserved in message, got %s", msg)
	}
}

// Scenario 8: Duplicate findings are safely deduplicated without inflating counts.
func TestSARIF_Conformance_8_DuplicateFindingsDeduplicated(t *testing.T) {
	findingA := Finding{
		ID:          "f-dup-1",
		Category:    "BOLA",
		Severity:    SeverityHigh,
		Title:       "BOLA Exposure",
		Endpoint:    "/api/orders/1",
		Fingerprint: "stable-fp-bola",
	}
	// Identical fingerprint/ID -> duplicate
	findingB := Finding{
		ID:          "f-dup-2",
		Category:    "BOLA",
		Severity:    SeverityHigh,
		Title:       "BOLA Exposure Duplicate",
		Endpoint:    "/api/orders/1",
		Fingerprint: "stable-fp-bola",
	}

	rep := Report{
		Findings: []Finding{findingA, findingB},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	if len(sarifLog.Runs[0].Results) != 1 {
		t.Errorf("expected duplicate finding to be deduplicated to 1 result, got %d", len(sarifLog.Runs[0].Results))
	}
}

// Scenario 9: Stable rule IDs and result references across different executions.
func TestSARIF_Conformance_9_StableRuleIDs(t *testing.T) {
	findings := []Finding{
		{ID: "f1", Category: "AUTH_BYPASS", Title: "Auth Bypass", Severity: SeverityCritical, Endpoint: "/auth", Fingerprint: "fp-1"},
		{ID: "f2", Category: "SSRF", Title: "Internal SSRF", Severity: SeverityHigh, Endpoint: "/proxy", Fingerprint: "fp-2"},
	}

	rep1 := Report{Findings: findings}
	rep2 := Report{Findings: []Finding{findings[1], findings[0]}} // reversed order

	data1, _ := GenerateSARIF(rep1)
	data2, _ := GenerateSARIF(rep2)

	var log1, log2 SARIFLog
	_ = json.Unmarshal(data1, &log1)
	_ = json.Unmarshal(data2, &log2)

	// Sorted rule list should be identical in both runs
	rules1 := log1.Runs[0].Tool.Driver.Rules
	rules2 := log2.Runs[0].Tool.Driver.Rules

	if len(rules1) != len(rules2) {
		t.Fatalf("rule count mismatch")
	}
	for i := range rules1 {
		if rules1[i].ID != rules2[i].ID {
			t.Errorf("rule order instability: log1[%d]=%s, log2[%d]=%s", i, rules1[i].ID, i, rules2[i].ID)
		}
	}
}

// Scenario 10: Policy metadata from Phase 8.2 included in SARIF run properties.
func TestSARIF_Conformance_10_PolicyMetadataCompliance(t *testing.T) {
	rep := Report{
		Target: "https://example.com",
		Metadata: map[string]any{
			"policy_evaluation": map[string]any{
				"passed":         true,
				"reliable":       true,
				"policy_name":    "Production CI Gate",
				"policy_version": "1.0",
				"policy_digest":  "a1b2c3d4e5f67890123456789abcdef012345678",
				"observed_counts": map[string]any{
					"CRITICAL": 0,
					"HIGH":     1,
				},
				"violations": []any{},
			},
		},
		Findings: []Finding{
			{ID: "f1", Category: "INFO_LEAK", Severity: SeverityHigh, Endpoint: "/api/info", Fingerprint: "fp-1"},
		},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	if err := ValidateSARIF(data); err != nil {
		t.Fatalf("schema validation failed for SARIF with policy metadata: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	runProps := sarifLog.Runs[0].Properties
	if runProps == nil {
		t.Fatalf("expected non-nil run properties")
	}
	if _, ok := runProps["policy_evaluation"]; !ok {
		t.Fatalf("expected policy_evaluation in run properties")
	}
}

// Scenario 11 & 12: Write failures on invalid output paths.
func TestSARIF_Conformance_11_12_InvalidOutputDestination(t *testing.T) {
	rep := Report{
		Findings: []Finding{
			{ID: "f1", Category: "TEST", Severity: SeverityLow, Endpoint: "/test", Fingerprint: "fp-1"},
		},
	}

	// Non-existent directory
	invalidPath := filepath.Join("Z:", "nonexistent_directory_987654321", "output.sarif")
	err := WriteSARIF(rep, invalidPath)
	if err == nil {
		t.Fatalf("expected file write failure for nonexistent directory")
	}
}

// Scenario 13: Schema validator correctly rejects invalid JSON and non-conforming SARIF.
func TestSARIF_Conformance_13_ValidatorRejection(t *testing.T) {
	// 1. Invalid JSON
	err := ValidateSARIF([]byte("not valid json {"))
	if err == nil || !strings.Contains(err.Error(), "JSON parse error") {
		t.Errorf("expected JSON parse error, got: %v", err)
	}

	// 2. Missing required 'version' field
	missingVersion := []byte(`{
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		"runs": []
	}`)
	err = ValidateSARIF(missingVersion)
	if err == nil {
		t.Errorf("expected validation failure for missing 'version'")
	}

	// 3. Invalid version string
	invalidVersion := []byte(`{
		"version": "1.0.0",
		"runs": []
	}`)
	err = ValidateSARIF(invalidVersion)
	if err == nil {
		t.Errorf("expected validation failure for invalid version '1.0.0'")
	}

	// 4. Invalid result level
	invalidResultLevel := []byte(`{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Felix"
					}
				},
				"results": [
					{
						"message": { "text": "Something happened" },
						"level": "FATAL_CATASTROPHE"
					}
				]
			}
		]
	}`)
	err = ValidateSARIF(invalidResultLevel)
	if err == nil {
		t.Errorf("expected validation failure for invalid result level")
	}

	// 5. Invalid physicalLocation URI with spaces
	invalidURI := []byte(`{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Felix"
					}
				},
				"results": [
					{
						"message": { "text": "Valid message" },
						"locations": [
							{
								"physicalLocation": {
									"artifactLocation": {
										"uri": "invalid uri with spaces and \\ backslashes"
									}
								}
							}
						]
					}
				]
			}
		]
	}`)
	err = ValidateSARIF(invalidURI)
	if err == nil {
		t.Errorf("expected validation failure for invalid physicalLocation URI")
	}
}

// Scenario 14: Real generated SARIF output passing the official schema validator.
func TestSARIF_Conformance_14_RealGeneratedOutput(t *testing.T) {
	rep := Report{
		Target: "https://shop.example.com",
		Findings: []Finding{
			{
				ID:          "FELIX-BOLA-2026-001",
				Title:       "Broken Object Level Authorization on Order Lookup",
				Category:    "BOLA",
				Severity:    SeverityCritical,
				Confidence:  ConfidenceHigh,
				Target:      "https://shop.example.com",
				Endpoint:    "/api/v2/orders/10492",
				Method:      "GET",
				Description: "Authenticated customer was able to view private order of another tenant.",
				Evidence:    "HTTP 200 OK returned customer PII and credit card last 4 digits.",
				Remediation: "Enforce ownership validation against the authenticated session token.",
				Fingerprint: "sha256-bola-10492-order",
				Verification: VerificationRecord{
					Status:             VerificationVerified,
					Result:             "BOLA vulnerability verified via secondary unprivileged token.",
					SafeCurlCommand:    "curl -s -H 'Authorization: Bearer <token>' https://shop.example.com/api/v2/orders/10492",
					ReproductionSteps:  []string{"1. Authenticate as User A", "2. Request User B's order ID 10492"},
					VerificationMethod: "Active cross-account verification",
				},
				Score: 92,
			},
			{
				ID:          "FELIX-CORS-2026-002",
				Title:       "Overly Permissive CORS Access-Control-Allow-Origin",
				Category:    "CORS",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceMedium,
				Target:      "https://shop.example.com",
				Endpoint:    "/api/v2/catalog",
				Method:      "OPTIONS",
				Description: "API reflects arbitrary Origin header with Access-Control-Allow-Credentials: true.",
				Evidence:    "Origin: https://evil.com resulted in Access-Control-Allow-Origin: https://evil.com",
				Remediation: "Restrict allowed origins to trusted corporate domains.",
				Fingerprint: "sha256-cors-catalog",
				Score:       55,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "production-audit.sarif")
	if err := WriteSARIF(rep, tmpFile); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	// Validate written file
	if err := ValidateSARIFFile(tmpFile); err != nil {
		t.Fatalf("ValidateSARIFFile failed for real written file: %v", err)
	}
}
