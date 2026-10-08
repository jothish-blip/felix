package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// findRepoRoot searches upward from current working directory until it locates go.mod.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// loadFixture reads a fixture file from the repository testdata directory.
func loadFixture(t *testing.T, relPath string) []byte {
	t.Helper()
	fullPath := filepath.Join(findRepoRoot(), relPath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", fullPath, err)
	}
	return data
}

// createTestJWT creates a signed-like test JWT token with specified claims.
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature-data-bytes-here-123456"))
	return header + "." + payload + "." + signature
}

// ============================================================================
// 1. SECRETS REGRESSION: FALSE-POSITIVE PROTECTION
// ============================================================================

func TestRegression_Secrets_FalsePositives(t *testing.T) {
	fixtureData := loadFixture(t, "testdata/regression/secrets/false_positives.js")
	detector := secrets.NewDetector()

	findings := detector.ScanContent("false_positives.js", fixtureData)
	if len(findings) > 0 {
		var msgs []string
		for _, f := range findings {
			msgs = append(msgs, fmt.Sprintf("Type=%s Value=%s Line=%d", f.Type, f.Value, f.LineNumber))
		}
		t.Fatalf("false-positive regression failed: expected 0 findings, got %d:\n%s", len(findings), strings.Join(msgs, "\n"))
	}

	// Subtest A: Specific regression for NexSpace Base64URL/nanoid alphabet lookup table
	t.Run("NexSpace_Alphabet_Table_Suppressed", func(t *testing.T) {
		nanoidAlphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		ctx := `const defaultAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";`
		if !secrets.IsStructuredAlphabet(nanoidAlphabet, ctx) {
			t.Errorf("IsStructuredAlphabet failed to identify NexSpace nanoid alphabet table")
		}
		if !secrets.IsFalsePositive(nanoidAlphabet, secrets.SecretHighEntropy, ctx) {
			t.Errorf("IsFalsePositive failed to filter NexSpace nanoid alphabet table")
		}
	})

	// Subtest B: Table-driven assertions on specific non-secret patterns
	fpCases := []struct {
		name       string
		candidate  string
		secretType secrets.SecretType
		context    string
	}{
		{
			name:       "Placeholder Secret Key",
			candidate:  "your_api_key_here",
			secretType: secrets.SecretHighEntropy,
			context:    "const api_key = ...",
		},
		{
			name:       "Placeholder Dummy Key",
			candidate:  "placeholder_dummy_key",
			secretType: secrets.SecretHighEntropy,
			context:    "const token = ...",
		},
		{
			name:       "Standard UUID v4",
			candidate:  "123e4567-e89b-12d3-a456-426614174000",
			secretType: secrets.SecretHighEntropy,
			context:    "const sessionId = ...",
		},
		{
			name:       "CSS rgba value",
			candidate:  "rgba(255, 255, 255, 0.85)",
			secretType: secrets.SecretHighEntropy,
			context:    "background-color: ...",
		},
		{
			name:       "CSS hex color code",
			candidate:  "#f4a261",
			secretType: secrets.SecretHighEntropy,
			context:    "border-color: ...",
		},
		{
			name:       "Webpack Chunk Identifier",
			candidate:  "webpackChunk_app_portal",
			secretType: secrets.SecretHighEntropy,
			context:    "window['webpackChunk_app_portal'] = ...",
		},
		{
			name:       "Standard Base64 Alphabet",
			candidate:  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
			secretType: secrets.SecretHighEntropy,
			context:    "const alphabet = ...",
		},
		{
			name:       "Bitcoin Base58 Alphabet",
			candidate:  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
			secretType: secrets.SecretHighEntropy,
			context:    "const alphabet = ...",
		},
	}

	for _, tc := range fpCases {
		t.Run(tc.name, func(t *testing.T) {
			if !secrets.IsFalsePositive(tc.candidate, tc.secretType, tc.context) {
				t.Errorf("candidate %q was NOT recognized as a false positive", tc.candidate)
			}
		})
	}
}

// ============================================================================
// 2. SECRETS REGRESSION: FALSE-NEGATIVE PROTECTION
// ============================================================================

func TestRegression_Secrets_TruePositives(t *testing.T) {
	fixtureData := loadFixture(t, "testdata/regression/secrets/true_positives.js")
	detector := secrets.NewDetector()

	findings := detector.ScanContent("true_positives.js", fixtureData)
	if len(findings) == 0 {
		t.Fatalf("false-negative regression failed: expected detections, got 0")
	}

	foundTypes := make(map[secrets.SecretType][]secrets.SecretFinding)
	for _, f := range findings {
		foundTypes[f.Type] = append(foundTypes[f.Type], f)
	}

	// 1. AWS Access Key
	t.Run("Detect_AWS_Access_Key", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretAWSAccessKey]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretAWSAccessKey detection, got none")
		}
		if fs[0].Value != "AKIA1234567890ABCDEF" {
			t.Errorf("unexpected value for AWS key: %s", fs[0].Value)
		}
		if fs[0].Severity != secrets.SeverityHigh {
			t.Errorf("expected HIGH severity, got %s", fs[0].Severity)
		}
	})

	// 2. GitHub Token
	t.Run("Detect_GitHub_Token", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretGitHubToken]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretGitHubToken detection, got none")
		}
		if fs[0].Value != "ghp_1234567890abcdefghijklmnopqrstuvwxyz" {
			t.Errorf("unexpected value for GitHub token: %s", fs[0].Value)
		}
	})

	// 3. Slack Bot Token
	t.Run("Detect_Slack_Token", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretSlackToken]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretSlackToken detection, got none")
		}
		if fs[0].Value != "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx" {
			t.Errorf("unexpected value for Slack token: %s", fs[0].Value)
		}
	})

	// 4. Stripe Live Key
	t.Run("Detect_Stripe_Live_Key", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretStripeLiveKey]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretStripeLiveKey detection, got none")
		}
		if fs[0].Value != "sk_live_51Abcdef1234567890abcdef1234567890" {
			t.Errorf("unexpected value for Stripe key: %s", fs[0].Value)
		}
		if fs[0].Severity != secrets.SeverityHigh {
			t.Errorf("expected HIGH severity, got %s", fs[0].Severity)
		}
	})

	// 5. High-Entropy Credential in Secret Context
	t.Run("Detect_HighEntropy_Secret", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretHighEntropy]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretHighEntropy detection, got none")
		}
		var foundSecretContext bool
		for _, f := range fs {
			if f.Value == "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=" {
				foundSecretContext = true
				break
			}
		}
		if !foundSecretContext {
			t.Errorf("expected 4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z= to be detected")
		}
	})

	// 6. Private Key Pattern
	t.Run("Detect_Private_Key", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretPrivateKey]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretPrivateKey detection, got none")
		}
		if fs[0].Severity != secrets.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", fs[0].Severity)
		}
	})

	// 7. Legitimate NexSpace Candidate Preservation
	t.Run("Preserve_NexSpace_Legitimate_Entropy_Candidate", func(t *testing.T) {
		fs, ok := foundTypes[secrets.SecretHighEntropy]
		if !ok || len(fs) == 0 {
			t.Fatalf("expected SecretHighEntropy detection, got none")
		}
		var foundNexSpaceCandidate bool
		for _, f := range fs {
			if strings.HasPrefix(f.Value, "sb_p") && strings.HasSuffix(f.Value, "ud_e") {
				foundNexSpaceCandidate = true
				if f.Severity != secrets.SeverityLow {
					t.Errorf("expected LOW severity for entropy candidate, got %s", f.Severity)
				}
				break
			}
		}
		if !foundNexSpaceCandidate {
			t.Errorf("legitimate NexSpace candidate (sb_p...ud_e) was improperly filtered out")
		}
	})

	// 8. Verification & Evidence Model Separation for Secrets
	t.Run("Secret_Report_Verification_Separation", func(t *testing.T) {
		for _, f := range findings {
			rf := report.FromSecretFinding("https://example.com", f)
			if rf.Verification.Status != report.VerificationNotVerified {
				t.Errorf("secret finding must be marked NOT_VERIFIED, got %s", rf.Verification.Status)
			}
			if rf.Verification.DetectionStatus != "DETECTED" {
				t.Errorf("secret finding must have DetectionStatus DETECTED, got %s", rf.Verification.DetectionStatus)
			}
			if rf.EvidenceDetails.NegativeEvidence == "" {
				t.Errorf("secret finding missing negative evidence note: %+v", rf)
			}
			if !strings.Contains(rf.EvidenceDetails.NegativeEvidence, "Static code analysis only") {
				t.Errorf("negative evidence must mention static analysis: %s", rf.EvidenceDetails.NegativeEvidence)
			}
		}
	})
}

// ============================================================================
// 3. CLOUD & BaaS REGRESSION: FALSE-POSITIVE & FALSE-NEGATIVE SCENARIOS
// ============================================================================

func TestRegression_Cloud_AssetDiscovery_FalsePositives(t *testing.T) {
	fixtureData := loadFixture(t, "testdata/regression/cloud/false_positives.js")
	services := cloud.DiscoverServicesFromContent("cloud_fp.js", fixtureData)

	if len(services) < 3 {
		t.Fatalf("expected at least 3 cloud services discovered, got %d", len(services))
	}

	var foundSupabase, foundFirebase, foundAWS bool
	for _, s := range services {
		switch s.Provider {
		case cloud.ProviderSupabase:
			foundSupabase = true
			if s.URL != "https://acme-prod.supabase.co" {
				t.Errorf("unexpected Supabase URL: %s", s.URL)
			}
		case cloud.ProviderFirebase:
			foundFirebase = true
		case cloud.ProviderAWS:
			foundAWS = true
		}

		// Cloud configuration discoveries must map to OBSERVED at INFO severity
		cf := cloud.CloudFinding{
			Provider:   s.Provider,
			Endpoint:   s.URL,
			Category:   "Cloud Provider Discovered",
			Severity:   cloud.SeverityInfo,
			Confidence: cloud.ConfidenceHigh,
		}
		rf := report.FromCloudFinding("https://example.com", cf)
		if rf.Verification.Status != report.VerificationObserved {
			t.Errorf("discovered cloud configuration must be OBSERVED, got %s", rf.Verification.Status)
		}
		if rf.Severity != report.SeverityInfo {
			t.Errorf("discovered cloud configuration must be INFO, got %s", rf.Severity)
		}
	}

	if !foundSupabase || !foundFirebase || !foundAWS {
		t.Errorf("expected discovery of Supabase, Firebase, and AWS; got Supabase=%v Firebase=%v AWS=%v",
			foundSupabase, foundFirebase, foundAWS)
	}
}

type cloudTestCase struct {
	ID                         string `json:"id"`
	Type                       string `json:"type"`
	Provider                   string `json:"provider"`
	Description                string `json:"description"`
	MockStatus                 int    `json:"mock_status"`
	MockBody                   string `json:"mock_body"`
	ExpectedDetectionStatus    string `json:"expected_detection_status"`
	ExpectedVerificationStatus string `json:"expected_verification_status"`
	ExpectedSeverity           string `json:"expected_severity"`
	ExpectExposure             bool   `json:"expect_exposure"`
}

func TestRegression_Cloud_Scenarios(t *testing.T) {
	casesData := loadFixture(t, "testdata/regression/cloud/cases.json")
	var testCases []cloudTestCase
	if err := json.Unmarshal(casesData, &testCases); err != nil {
		t.Fatalf("failed to parse cloud test cases: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.ID, func(t *testing.T) {
			switch tc.Provider {
			case "supabase":
				testCloudSupabaseScenario(t, tc)
			case "firebase":
				testCloudFirebaseScenario(t, tc)
			case "aws":
				testCloudAWSScenario(t, tc)
			}
		})
	}
}

func testCloudSupabaseScenario(t *testing.T, tc cloudTestCase) {
	// Case 1: Service role key detection (strictly zero live requests)
	if tc.ID == "cloud_fn_supabase_service_role_key" {
		var liveRequests int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&liveRequests, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serviceRoleToken := createTestJWT(map[string]interface{}{
			"iss":  "supabase",
			"role": "service_role",
		})

		svc := cloud.Service{
			Provider: cloud.ProviderSupabase,
			URL:      server.URL,
		}
		client := cloud.NewClient(cloud.ClientOptions{HTTPClient: server.Client()})
		findings := cloud.AuditSupabase(context.Background(), client, svc, nil, "", serviceRoleToken)

		if len(findings) == 0 {
			t.Fatalf("expected service_role finding, got 0")
		}
		if findings[0].Severity != cloud.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
		}
		if count := atomic.LoadInt32(&liveRequests); count != 0 {
			t.Errorf("detector must NEVER send requests with service_role key; saw %d requests", count)
		}
		return
	}

	// Case 2: Endpoint probing scenarios (401, 403, 200 empty, 200 records)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tc.MockStatus)
		fmt.Fprint(w, tc.MockBody)
	}))
	defer server.Close()

	svc := cloud.Service{
		Provider: cloud.ProviderSupabase,
		URL:      server.URL,
	}
	client := cloud.NewClient(cloud.ClientOptions{HTTPClient: server.Client()})
	findings := cloud.AuditSupabase(context.Background(), client, svc, []string{"/rest/v1/data"}, "mock-anon-key", "")

	if tc.Type == "false_positive" {
		for _, f := range findings {
			if f.Category == "Unauthorized Data Exposure" {
				t.Errorf("%s: protected resource (status %d) was reported as unauthorized data exposure: %+v", tc.ID, tc.MockStatus, f)
			}
		}
		// If probe returned 401 or 403, verify that an access-denied cloud finding maps to NOT_EXPOSED
		if tc.MockStatus == 401 || tc.MockStatus == 403 {
			mockDenied := cloud.CloudFinding{
				Provider: cloud.ProviderSupabase,
				Category: "RLS Enforced / Access Denied (HTTP 401/403)",
				Endpoint: server.URL + "/rest/v1/data",
				Severity: cloud.SeverityInfo,
			}
			rf := report.FromCloudFinding("https://example.com", mockDenied)
			if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
				t.Errorf("%s: expected verification status %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
			}
		}
	} else if tc.Type == "true_positive" && tc.ExpectExposure {
		var foundExposure bool
		for _, f := range findings {
			if f.Category == "Unauthorized Data Exposure" {
				foundExposure = true
				rf := report.FromCloudFinding("https://example.com", f)
				if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
					t.Errorf("%s: expected verification status %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
				}
				if string(rf.Severity) != tc.ExpectedSeverity {
					t.Errorf("%s: expected severity %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
				}
			}
		}
		if !foundExposure {
			t.Errorf("%s: expected unauthorized data exposure finding, got none", tc.ID)
		}
	}
}

func testCloudFirebaseScenario(t *testing.T, tc cloudTestCase) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tc.MockStatus)
		fmt.Fprint(w, tc.MockBody)
	}))
	defer server.Close()

	svc := cloud.Service{
		Provider: cloud.ProviderFirebase,
		URL:      server.URL,
	}
	client := cloud.NewClient(cloud.ClientOptions{HTTPClient: server.Client()})
	findings := cloud.AuditFirebase(context.Background(), client, svc)

	if tc.Type == "false_positive" {
		for _, f := range findings {
			if f.Category == "Unauthorized Data Exposure" {
				t.Errorf("%s: protected Firebase endpoint reported as unauthorized exposure: %+v", tc.ID, f)
			}
		}
	} else if tc.Type == "true_positive" {
		if len(findings) == 0 {
			t.Fatalf("%s: expected open database exposure finding, got 0", tc.ID)
		}
		rf := report.FromCloudFinding("https://example.com", findings[0])
		if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
			t.Errorf("%s: expected verification status %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
		}
		if string(rf.Severity) != tc.ExpectedSeverity {
			t.Errorf("%s: expected severity %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
		}
	}
}

func testCloudAWSScenario(t *testing.T, tc cloudTestCase) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(tc.MockBody, "<ListBucketResult>") {
			w.Header().Set("Content-Type", "application/xml")
		}
		w.WriteHeader(tc.MockStatus)
		fmt.Fprint(w, tc.MockBody)
	}))
	defer server.Close()

	svc := cloud.Service{
		Provider: cloud.ProviderAWS,
		URL:      server.URL,
	}
	client := cloud.NewClient(cloud.ClientOptions{HTTPClient: server.Client()})
	findings := cloud.AuditStorage(context.Background(), client, svc)

	if tc.Type == "false_positive" {
		for _, f := range findings {
			if f.Category == "Anonymous Bucket Listing" {
				t.Errorf("%s: protected S3 bucket reported as public bucket: %+v", tc.ID, f)
			}
		}
	} else if tc.Type == "true_positive" {
		if len(findings) == 0 {
			t.Fatalf("%s: expected public S3 bucket finding, got 0", tc.ID)
		}
		rf := report.FromCloudFinding("https://example.com", findings[0])
		if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
			t.Errorf("%s: expected verification status %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
		}
		if string(rf.Severity) != tc.ExpectedSeverity {
			t.Errorf("%s: expected severity %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
		}
	}
}

// ============================================================================
// 4. API & ENDPOINT REGRESSION: FALSE-POSITIVE & FALSE-NEGATIVE SCENARIOS
// ============================================================================

type apiTestCase struct {
	ID                         string            `json:"id"`
	Type                       string            `json:"type"`
	Category                   string            `json:"category"`
	Path                       string            `json:"path"`
	Description                string            `json:"description"`
	MockStatus                 int               `json:"mock_status"`
	MockHeaders                map[string]string `json:"mock_headers"`
	MockBody                   string            `json:"mock_body"`
	ExpectedDetectionStatus    string            `json:"expected_detection_status"`
	ExpectedVerificationStatus string            `json:"expected_verification_status"`
	ExpectedSeverity           string            `json:"expected_severity"`
	ExpectExposure             bool              `json:"expect_exposure"`
}

func TestRegression_API_Scenarios(t *testing.T) {
	casesData := loadFixture(t, "testdata/regression/api/cases.json")
	var testCases []apiTestCase
	if err := json.Unmarshal(casesData, &testCases); err != nil {
		t.Fatalf("failed to parse api test cases: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.ID, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.Path != "" && tc.Category != "cors" && r.URL.Path != tc.Path {
					http.NotFound(w, r)
					return
				}
				for k, v := range tc.MockHeaders {
					w.Header().Set(k, v)
				}
				if tc.Category == "cors" && r.Header.Get("Origin") != "" {
					if acao, ok := tc.MockHeaders["Access-Control-Allow-Origin"]; ok && acao != "*" {
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					}
				}
				w.WriteHeader(tc.MockStatus)
				fmt.Fprint(w, tc.MockBody)
			}))
			defer server.Close()

			client := api.NewClient(api.ClientOptions{HTTPClient: server.Client()})

			switch tc.Category {
			case "graphql":
				findings := api.AuditGraphQL(context.Background(), client, server.URL, []string{tc.Path})
				if tc.Type == "false_positive" {
					if len(findings) != 0 {
						t.Errorf("%s: protected GraphQL endpoint produced exposure findings: %+v", tc.ID, findings)
					}
				} else {
					if len(findings) == 0 {
						t.Fatalf("%s: expected GraphQL introspection finding, got 0", tc.ID)
					}
					rf := report.FromAPIFinding("https://example.com", findings[0])
					if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
						t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
					}
					if string(rf.Severity) != tc.ExpectedSeverity {
						t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
					}
				}

			case "cors":
				findings := api.AuditCORS(context.Background(), client, server.URL)
				if len(findings) == 0 {
					t.Fatalf("%s: expected CORS finding, got 0", tc.ID)
				}
				rf := report.FromAPIFinding("https://example.com", findings[0])
				if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
					t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
				}
				if string(rf.Severity) != tc.ExpectedSeverity {
					t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
				}
				if tc.Type == "false_positive" {
					if rf.EvidenceDetails.NegativeEvidence == "" {
						t.Errorf("%s: expected negative evidence explaining credential absence", tc.ID)
					}
				}

			case "sensitive-path", "api-docs", "health", "metrics":
				findings := api.AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{tc.Path})
				if tc.Type == "false_positive" && tc.MockStatus >= 400 {
					for _, f := range findings {
						if f.Category == api.CategoryEnvExposure || f.Category == api.CategoryGitExposure {
							t.Errorf("%s: non-exposed endpoint produced critical finding: %+v", tc.ID, f)
						}
					}
				} else if len(findings) > 0 {
					rf := report.FromAPIFinding("https://example.com", findings[0])
					if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
						t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
					}
					if string(rf.Severity) != tc.ExpectedSeverity {
						t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
					}
				}

			case "endpoint-discovered":
				h := make(http.Header)
				for k, v := range tc.MockHeaders {
					h.Set(k, v)
				}
				authRes := api.ReasonAuthState(tc.MockStatus, h, []byte(tc.MockBody))
				if string(authRes.State) != tc.ExpectedDetectionStatus {
					t.Errorf("%s: expected auth state %s, got %s", tc.ID, tc.ExpectedDetectionStatus, authRes.State)
				}
				finding := api.APIFinding{
					Category:       api.CategoryEndpointDiscovered,
					Endpoint:       tc.Path,
					Severity:       api.SeverityInfo,
					Confidence:     api.ConfidenceMedium,
					Classification: api.ClassifyEndpoint(tc.Path),
					AuthState:      authRes.State,
					SourceAsset:    "bundle.js",
					Mechanism:      "fetch",
				}
				rf := report.FromAPIFinding("https://example.com", finding)
				if string(rf.Verification.Status) != tc.ExpectedVerificationStatus {
					t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedVerificationStatus, rf.Verification.Status)
				}
				if string(rf.Severity) != tc.ExpectedSeverity {
					t.Errorf("%s: expected %s, got %s", tc.ID, tc.ExpectedSeverity, rf.Severity)
				}
			}
		})
	}
}

// ============================================================================
// 5. REPORT & CORRELATION REGRESSION SCENARIOS
// ============================================================================

type reportTestCase struct {
	ID                       string           `json:"id"`
	Description              string           `json:"description"`
	Findings                 []report.Finding `json:"findings"`
	ExpectedStoriesCount     int              `json:"expected_stories_count"`
	ExpectedStoryIDPrefix    string           `json:"expected_story_id_prefix"`
	ExpectedMaxStorySeverity string           `json:"expected_max_story_severity"`
	ExpectedMaxRiskLevel     string           `json:"expected_max_risk_level"`
}

func TestRegression_Report_Correlation_Scenarios(t *testing.T) {
	casesData := loadFixture(t, "testdata/regression/report/cases.json")
	var testCases []reportTestCase
	if err := json.Unmarshal(casesData, &testCases); err != nil {
		t.Fatalf("failed to parse report test cases: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.ID, func(t *testing.T) {
			_, stories := report.Correlate("https://example.com", tc.Findings)

			if len(stories) != tc.ExpectedStoriesCount {
				t.Fatalf("%s: expected %d security stories, got %d", tc.ID, tc.ExpectedStoriesCount, len(stories))
			}

			if tc.ExpectedStoriesCount > 0 {
				s := stories[0]
				if tc.ExpectedStoryIDPrefix != "" && !strings.HasPrefix(s.ID, tc.ExpectedStoryIDPrefix) {
					t.Errorf("%s: expected story ID prefix %s, got %s", tc.ID, tc.ExpectedStoryIDPrefix, s.ID)
				}
				if tc.ExpectedMaxStorySeverity != "" && string(s.Severity) != tc.ExpectedMaxStorySeverity {
					t.Errorf("%s: expected story severity %s, got %s", tc.ID, tc.ExpectedMaxStorySeverity, s.Severity)
				}
			}

			// Validate complete report build and JSON/HTML export
			score, level := report.CalculateReportRisk(tc.Findings, stories)
			if tc.ExpectedMaxRiskLevel != "" && level != tc.ExpectedMaxRiskLevel {
				t.Errorf("%s: expected risk level %s, got %s (score=%d)", tc.ID, tc.ExpectedMaxRiskLevel, level, score)
			}

			rep := report.BuildReport("https://example.com", tc.Findings)
			jsonBytes, err := report.GenerateJSON(rep)
			if err != nil {
				t.Fatalf("%s: failed to export JSON: %v", tc.ID, err)
			}
			if len(jsonBytes) == 0 {
				t.Errorf("%s: exported JSON was empty", tc.ID)
			}

			htmlStr, err := report.GenerateHTML(rep)
			if err != nil {
				t.Fatalf("%s: failed to export HTML: %v", tc.ID, err)
			}
			if len(htmlStr) == 0 {
				t.Errorf("%s: exported HTML was empty", tc.ID)
			}
		})
	}
}

// ============================================================================
// 6. PIPELINE INTEGRATION REGRESSION: END-TO-END ARTIFACT REPRODUCTION
// ============================================================================

func TestRegression_Pipeline_EndToEnd(t *testing.T) {
	// Ingest synthetic assets mimicking a modern web application
	syntheticAssets := []crawler.Asset{
		{
			URL:         "https://target.corp/bundle.js",
			ContentType: "application/javascript",
			Content:     loadFixture(t, "testdata/regression/secrets/false_positives.js"),
		},
		{
			URL:         "https://target.corp/cloud-cfg.js",
			ContentType: "application/javascript",
			Content:     loadFixture(t, "testdata/regression/cloud/false_positives.js"),
		},
	}

	// 1. Secrets analysis on false positives: must produce 0 findings
	secretDetector := secrets.NewDetector()
	var secretFindings []secrets.SecretFinding
	for _, a := range syntheticAssets {
		secretFindings = append(secretFindings, secretDetector.ScanContent(a.URL, a.Content)...)
	}
	if len(secretFindings) != 0 {
		t.Fatalf("end-to-end secret ingestion on false-positive bundle produced %d findings", len(secretFindings))
	}

	// 2. Cloud discovery on false positives: must produce only OBSERVED/INFO findings
	cloudDetector := cloud.NewDetector(nil)
	cloudServices := cloudDetector.DiscoverServices(syntheticAssets)
	if len(cloudServices) == 0 {
		t.Fatalf("end-to-end cloud discovery found 0 services in cloud-cfg.js")
	}

	var normalizedFindings []report.Finding
	for _, s := range cloudServices {
		cf := cloud.CloudFinding{
			Provider:   s.Provider,
			Endpoint:   s.URL,
			Category:   "Cloud Provider Discovered",
			Severity:   cloud.SeverityInfo,
			Confidence: cloud.ConfidenceHigh,
		}
		normalizedFindings = append(normalizedFindings, report.FromCloudFinding("https://target.corp", cf))
	}

	// 3. Correlate and verify: zero stories, clean low-risk report
	normalizedFindings, stories := report.Correlate("https://target.corp", normalizedFindings)
	if len(stories) != 0 {
		t.Errorf("expected 0 security stories from pure configuration discoveries, got %d", len(stories))
	}

	finalReport := report.BuildReport("https://target.corp", normalizedFindings)
	if finalReport.RiskLevel != "LOW" && finalReport.RiskLevel != "INFORMATIONAL" {
		t.Errorf("expected LOW/INFORMATIONAL risk level for non-vulnerable assets, got %s (score=%d)", finalReport.RiskLevel, finalReport.RiskScore)
	}
}

// ============================================================================
// 7. PHASE B REGRESSION: ENDPOINT EXTRACTION, SPA, CLASSIFICATION & AUTH STATE
// ============================================================================

func TestRegression_PhaseB_DiscoveryAndIntelligence(t *testing.T) {
	target := "https://webjothishanalyst.site"

	// 1. JavaScript Endpoint Extraction & Normalization
	t.Run("EndpointExtraction_Comprehensive", func(t *testing.T) {
		jsCode := `
			// Standard calls
			fetch("/api/v1/users");
			fetch('/api/auth/token', { method: "POST" });
			axios.get("/api/products");
			axios.post("/api/checkout");
			axios.request({ url: "/api/data", method: "POST" });

			// Dynamic template literals & colon params
			fetch(` + "`" + `/api/users/${userId}` + "`" + `);
			fetch(` + "`" + `/api/projects/${projectId}/tasks` + "`" + `);

			// Base URL concatenation
			const API_BASE = "/api/v2";
			fetch(API_BASE + "/inventory");

			// Absolute same-origin vs out-of-scope third-party
			fetch("https://webjothishanalyst.site/api/projects");
			fetch("https://api.thirdparty-analytics.com/collect");

			// Operational endpoints
			fetch("/healthz");
			fetch("/actuator/prometheus");
			fetch("/api/webhook/stripe");
		`

		endpoints := api.ExtractEndpointsFromJS("app.js", []byte(jsCode), target)
		if len(endpoints) == 0 {
			t.Fatalf("expected extracted endpoints, got 0")
		}

		epMap := make(map[string]api.DiscoveredEndpoint)
		for _, ep := range endpoints {
			epMap[ep.Path] = ep
		}

		// Verify extraction
		expectedPaths := []struct {
			path               string
			expectedMethod     string
			expectedClass      api.EndpointClassification
			staticallyResolved bool
		}{
			{"/api/v1/users", "UNKNOWN", api.ClassUser, true},
			{"/api/auth/token", "POST", api.ClassAuthentication, true},
			{"/api/products", "GET", api.ClassAPI, true},
			{"/api/checkout", "POST", api.ClassPayment, true},
			{"/api/data", "POST", api.ClassAPI, true},
			{"/api/users/{param}", "UNKNOWN", api.ClassUser, false},
			{"/api/projects/{param}/tasks", "UNKNOWN", api.ClassAPI, false},
			{"/api/v2/inventory", "UNKNOWN", api.ClassAPI, true},
			{"/api/projects", "UNKNOWN", api.ClassAPI, true},
			{"/healthz", "UNKNOWN", api.ClassHealth, true},
			{"/actuator/prometheus", "UNKNOWN", api.ClassMetrics, true},
			{"/api/webhook/stripe", "UNKNOWN", api.ClassWebhook, true},
		}

		for _, exp := range expectedPaths {
			ep, exists := epMap[exp.path]
			if !exists {
				t.Errorf("missing expected endpoint: %s", exp.path)
				continue
			}
			if ep.Method != exp.expectedMethod {
				t.Errorf("%s: expected method %s, got %s", exp.path, exp.expectedMethod, ep.Method)
			}
			if ep.Classification != exp.expectedClass {
				t.Errorf("%s: expected classification %s, got %s", exp.path, exp.expectedClass, ep.Classification)
			}
			if ep.StaticallyResolved != exp.staticallyResolved {
				t.Errorf("%s: expected StaticallyResolved=%v, got %v", exp.path, exp.staticallyResolved, ep.StaticallyResolved)
			}
		}

		// Verify third-party URL was NOT extracted
		for path := range epMap {
			if strings.Contains(path, "thirdparty") {
				t.Errorf("third-party endpoint leaked into extracted routes: %s", path)
			}
		}
	})

	// 2. SPA Route & Source Map Discovery
	t.Run("SPARouteAndSourceMapDiscovery", func(t *testing.T) {
		routerJS := `
			const routes = [
				{ path: '/dashboard', component: Dashboard },
				{ path: '/admin/settings', component: AdminSettings },
				{ path: '/profile/:userId', component: Profile }
			];
			const nextRoute = "/_next/data/build123/projects.json";
		`
		routes := api.DiscoverSPARoutes("router.js", []byte(routerJS), target)
		routeMap := make(map[string]bool)
		for _, r := range routes {
			routeMap[r.Path] = true
		}

		if !routeMap["/dashboard"] {
			t.Errorf("missing SPA route /dashboard")
		}
		if !routeMap["/admin/settings"] {
			t.Errorf("missing SPA route /admin/settings")
		}
		if !routeMap["/profile/{param}"] {
			t.Errorf("missing parameterized SPA route /profile/{param}")
		}
		if !routeMap["/_next/data/build123/projects.json"] {
			t.Errorf("missing Next.js data route")
		}

		// Source map extraction
		sourceMapJSON := `{
			"version": 3,
			"file": "bundle.js",
			"sources": ["src/api.ts"],
			"sourcesContent": ["const API = '/api/internal/config'; fetch('/api/v3/metrics');"]
		}`
		smEndpoints := api.ExtractEndpointsFromSourceMap("bundle.js.map", []byte(sourceMapJSON), target)
		smMap := make(map[string]bool)
		for _, ep := range smEndpoints {
			smMap[ep.Path] = true
		}
		if !smMap["/api/internal/config"] {
			t.Errorf("missing sourcemap endpoint /api/internal/config")
		}
		if !smMap["/api/v3/metrics"] {
			t.Errorf("missing sourcemap endpoint /api/v3/metrics")
		}
	})

	// 3. Classification Full Coverage & Severity Invariance
	t.Run("EndpointClassification_FullTaxonomy", func(t *testing.T) {
		taxonomyTests := map[string]api.EndpointClassification{
			"/api/auth/login":         api.ClassAuthentication,
			"/api/auth/session":       api.ClassAuthentication,
			"/api/oauth/authorize":    api.ClassAuthentication,
			"/auth/roles":             api.ClassAuthorization,
			"/auth/permissions":       api.ClassAuthorization,
			"/auth/service":           api.ClassAuth,
			"/api/users":              api.ClassUser,
			"/api/users/profile":      api.ClassUser,
			"/admin/dashboard":        api.ClassAdmin,
			"/api/account/settings":   api.ClassAccount,
			"/api/billing/invoices":   api.ClassPayment,
			"/api/checkout":           api.ClassPayment,
			"/graphql":                api.ClassGraphQL,
			"/api/upload/avatar":      api.ClassUpload,
			"/api/export/download":    api.ClassDownload,
			"/api/search":             api.ClassSearch,
			"/api/webhook/stripe":     api.ClassWebhook,
			"/actuator/health":        api.ClassHealth,
			"/actuator/prometheus":    api.ClassMetrics,
			"/swagger.json":           api.ClassDocumentation,
			"/bundle.js":              api.ClassStatic,
			"/logo.png":               api.ClassStatic,
			"/api/custom/resource":    api.ClassAPI,
			"/unrecognized/route":     api.ClassUnknown,
		}

		for path, expectedClass := range taxonomyTests {
			got := api.ClassifyEndpoint(path)
			if got != expectedClass {
				t.Errorf("%s: expected classification %s, got %s", path, expectedClass, got)
			}

			// Verify classification never changes severity beyond INFO
			finding := api.APIFinding{
				Category:       api.CategoryEndpointDiscovered,
				Endpoint:       path,
				Severity:       api.SeverityInfo,
				Confidence:     api.ConfidenceMedium,
				Classification: got,
				AuthState:      api.AuthStateUnknown,
			}
			rf := report.FromAPIFinding(target, finding)
			if rf.Severity != report.SeverityInfo {
				t.Errorf("%s: classification increased severity to %s (must be INFO)", path, rf.Severity)
			}
		}
	})

	// 4. Authentication-State Reasoning & Evidence Semantics
	t.Run("AuthStateReasoning_EvidenceModel", func(t *testing.T) {
		states := []struct {
			status       int
			headers      map[string]string
			body         string
			expectedAuth api.AuthState
			expectedVer  report.VerificationStatus
		}{
			{200, map[string]string{"Content-Type": "application/json"}, `{"ok":true}`, api.AuthStatePublic, report.VerificationObserved},
			{401, map[string]string{"WWW-Authenticate": "Bearer"}, `{"error":"unauthorized"}`, api.AuthStateAuthRequired, report.VerificationNotExposed},
			{403, map[string]string{"Content-Type": "text/plain"}, `Forbidden`, api.AuthStateForbidden, report.VerificationNotExposed},
			{404, map[string]string{"Content-Type": "text/html"}, `<html>Not Found</html>`, api.AuthStateNotFound, report.VerificationNotExposed},
			{302, map[string]string{"Location": "/login"}, ``, api.AuthStateRedirect, report.VerificationObserved},
			{500, map[string]string{}, `Internal Server Error`, api.AuthStateUnknown, report.VerificationObserved},
		}

		for _, s := range states {
			h := make(http.Header)
			for k, v := range s.headers {
				h.Set(k, v)
			}
			authRes := api.ReasonAuthState(s.status, h, []byte(s.body))
			if authRes.State != s.expectedAuth {
				t.Errorf("status %d: expected auth state %s, got %s", s.status, s.expectedAuth, authRes.State)
			}

			finding := api.APIFinding{
				Category:       api.CategoryEndpointDiscovered,
				Endpoint:       "/api/test",
				Severity:       api.SeverityInfo,
				Confidence:     api.ConfidenceMedium,
				Classification: api.ClassAPI,
				AuthState:      authRes.State,
				SourceAsset:    "app.js",
				Mechanism:      "fetch",
			}
			rf := report.FromAPIFinding(target, finding)
			if rf.Verification.Status != s.expectedVer {
				t.Errorf("status %d: expected verification status %s, got %s", s.status, s.expectedVer, rf.Verification.Status)
			}

			// Verify details contains Phase B metadata
			if rf.EvidenceDetails.Details["classification"] != string(api.ClassAPI) {
				t.Errorf("status %d: missing classification in evidence details", s.status)
			}
			if rf.EvidenceDetails.Details["auth_state"] != string(s.expectedAuth) {
				t.Errorf("status %d: missing auth_state in evidence details", s.status)
			}
		}
	})
}
