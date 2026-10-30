package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Helper to build a valid sample YAML profile string
func sampleValidYAML(baseURL string) string {
	return fmt.Sprintf(`version: 1
target:
  name: "Multi-Tenant Enterprise Portal"
  base_urls:
    - "%s"
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
  allowed_methods:
    - "GET"
    - "HEAD"
    - "OPTIONS"

safety:
  mode: "non_destructive"
  require_explicit_authorization: true
  allow_cross_tenant_checks: true
  max_requests: 50
  requests_per_second: 10
  timeout_seconds: 5
  follow_redirects: false

tenants:
  - id: "tenant_alpha"
    identity: "alpha-operator@example.corp"
    credential_env: "FELIX_TEST_TOKEN_ALPHA"
    headers:
      X-Tenant-Header: "Alpha"
    resource_ids:
      - "doc_alpha_101"
      - "doc_alpha_102"
  - id: "tenant_beta"
    identity: "beta-auditor@example.corp"
    credential_env: "FELIX_TEST_TOKEN_BETA"
    headers:
      X-Tenant-Header: "Beta"
    resource_ids:
      - "doc_beta_201"

cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "tenant_beta"
      resource_owner_tenant: "tenant_alpha"
      resource_id: "doc_alpha_101"
      path: "/api/v1/documents/{id}"
      method: "GET"
      expected_marker: "CONFIDENTIAL_ALPHA_DATA"
`, baseURL)
}

// 1. TestTargetProfile_ValidYAML: parse and validate valid YAML
func TestTargetProfile_ValidYAML(t *testing.T) {
	yamlStr := sampleValidYAML("http://127.0.0.1:8080")
	p, err := ParseTargetProfile([]byte(yamlStr))
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if p.Version != 1 {
		t.Errorf("expected version 1, got %d", p.Version)
	}
	if p.Target.Name != "Multi-Tenant Enterprise Portal" {
		t.Errorf("expected target name 'Multi-Tenant Enterprise Portal', got %q", p.Target.Name)
	}
	if len(p.Tenants) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(p.Tenants))
	}
	if len(p.CrossTenantTests.Comparisons) != 1 {
		t.Errorf("expected 1 comparison, got %d", len(p.CrossTenantTests.Comparisons))
	}
}

// 2. TestTargetProfile_ValidJSON: parse and validate valid JSON
func TestTargetProfile_ValidJSON(t *testing.T) {
	jsonStr := `{
		"version": 1,
		"target": {
			"name": "JSON API",
			"base_urls": ["http://127.0.0.1:8080"],
			"allowed_hosts": ["127.0.0.1"],
			"allowed_methods": ["GET"]
		},
		"safety": {
			"mode": "non_destructive",
			"allow_cross_tenant_checks": true,
			"max_requests": 20,
			"requests_per_second": 5,
			"timeout_seconds": 10
		},
		"tenants": [
			{"id": "t1", "identity": "user1", "credential_env": "T1_TOKEN", "resource_ids": ["r1"]},
			{"id": "t2", "identity": "user2", "credential_env": "T2_TOKEN", "resource_ids": ["r2"]}
		],
		"cross_tenant_tests": {
			"enabled": true,
			"comparisons": [
				{"requester_tenant": "t1", "resource_owner_tenant": "t2", "resource_id": "r2"}
			]
		}
	}`
	p, err := ParseTargetProfile([]byte(jsonStr))
	if err != nil {
		t.Fatalf("unexpected JSON parse error: %v", err)
	}
	if p.Version != 1 || len(p.Tenants) != 2 {
		t.Errorf("unexpected parsed structure: %+v", p)
	}
}

// 3. TestTargetProfile_UnsupportedVersion
func TestTargetProfile_UnsupportedVersion(t *testing.T) {
	yamlStr := sampleValidYAML("http://127.0.0.1:8080")
	yamlStr = strings.Replace(yamlStr, "version: 1", "version: 2", 1)
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unsupported profile version") {
		t.Fatalf("expected unsupported version error, got: %v", err)
	}
}

// 4. TestTargetProfile_MalformedYAML
func TestTargetProfile_MalformedYAML(t *testing.T) {
	malformed := `version: 1
target:
  name: "Bad Indent
    base_urls:
`
	_, err := ParseTargetProfile([]byte(malformed))
	if err == nil {
		t.Fatal("expected malformed YAML error, got nil")
	}
}

// 5. TestTargetProfile_OversizedProfile
func TestTargetProfile_OversizedProfile(t *testing.T) {
	oversized := make([]byte, MaxProfileFileSize+10)
	for i := range oversized {
		oversized[i] = ' '
	}
	_, err := ParseTargetProfile(oversized)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size limit") {
		t.Fatalf("expected oversized error, got: %v", err)
	}
}

// 6. TestTargetProfile_EmptyData
func TestTargetProfile_EmptyData(t *testing.T) {
	_, err := ParseTargetProfile([]byte(""))
	if err == nil || !strings.Contains(err.Error(), "empty profile data") {
		t.Fatalf("expected empty data error, got: %v", err)
	}
}

// 7. TestTargetProfile_EmptyBaseURLs
func TestTargetProfile_EmptyBaseURLs(t *testing.T) {
	yamlStr := `version: 1
target:
  name: "No URLs"
  base_urls: []
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "target.base_urls cannot be empty") {
		t.Fatalf("expected empty base_urls error, got: %v", err)
	}
}

// 8. TestTargetProfile_InvalidBaseURL_NoSchemeOrHost
func TestTargetProfile_InvalidBaseURL_NoSchemeOrHost(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls:
    - "example.com/no/scheme"
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "invalid target base_url") {
		t.Fatalf("expected invalid base_url error, got: %v", err)
	}
}

// 9. TestTargetProfile_InvalidBaseURL_UnsupportedScheme
func TestTargetProfile_InvalidBaseURL_UnsupportedScheme(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls:
    - "ftp://example.com/api"
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("expected unsupported scheme error, got: %v", err)
	}
}

// 10. TestTargetProfile_InvalidBaseURL_EmbeddedCredentials
func TestTargetProfile_InvalidBaseURL_EmbeddedCredentials(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls:
    - "http://admin:secret@127.0.0.1:8080"
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "must not contain embedded user credentials") {
		t.Fatalf("expected embedded credentials rejection, got: %v", err)
	}
}

// 11. TestTargetProfile_ProhibitedMutatingMethodInAllowedMethods
func TestTargetProfile_ProhibitedMutatingMethodInAllowedMethods(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		yamlStr := fmt.Sprintf(`version: 1
target:
  base_urls: ["http://127.0.0.1"]
  allowed_methods: ["GET", %q]
safety:
  mode: "non_destructive"
`, m)
		_, err := ParseTargetProfile([]byte(yamlStr))
		if err == nil || !strings.Contains(err.Error(), "destructive/mutating method") {
			t.Fatalf("expected rejection for mutating method %s, got: %v", m, err)
		}
	}
}

// 12. TestTargetProfile_UnsupportedMethodInAllowedMethods
func TestTargetProfile_UnsupportedMethodInAllowedMethods(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
  allowed_methods: ["CONNECT"]
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("expected unsupported method rejection, got: %v", err)
	}
}

// 13. TestTargetProfile_InvalidSafetyMode
func TestTargetProfile_InvalidSafetyMode(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "aggressive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "invalid safety mode") {
		t.Fatalf("expected invalid safety mode rejection, got: %v", err)
	}
}

// 14. TestTargetProfile_SafetyBounds_MaxRequests
func TestTargetProfile_SafetyBounds_MaxRequests(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
  max_requests: 50000
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "max_requests must be between") {
		t.Fatalf("expected max_requests bound rejection, got: %v", err)
	}
}

// 15. TestTargetProfile_SafetyBounds_RequestsPerSecond
func TestTargetProfile_SafetyBounds_RequestsPerSecond(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
  requests_per_second: 1000
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "requests_per_second must be between") {
		t.Fatalf("expected requests_per_second bound rejection, got: %v", err)
	}
}

// 16. TestTargetProfile_SafetyBounds_Timeout
func TestTargetProfile_SafetyBounds_Timeout(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
  timeout_seconds: 500
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "timeout_seconds must be between") {
		t.Fatalf("expected timeout_seconds bound rejection, got: %v", err)
	}
}

// 17. TestTargetProfile_MaxTenantsCount
func TestTargetProfile_MaxTenantsCount(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("version: 1\ntarget:\n  base_urls: [\"http://127.0.0.1\"]\nsafety:\n  mode: \"non_destructive\"\ntenants:\n")
	for i := 0; i < 55; i++ {
		sb.WriteString(fmt.Sprintf("  - id: \"tenant_%d\"\n    identity: \"t%d\"\n", i, i))
	}
	_, err := ParseTargetProfile([]byte(sb.String()))
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum tenant limit") {
		t.Fatalf("expected tenant limit error, got: %v", err)
	}
}

// 18. TestTargetProfile_DuplicateTenantID
func TestTargetProfile_DuplicateTenantID(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "dup_tenant"
    identity: "user1"
  - id: "dup_tenant"
    identity: "user2"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "duplicate tenant id") {
		t.Fatalf("expected duplicate tenant id rejection, got: %v", err)
	}
}

// 19. TestTargetProfile_EmptyTenantID
func TestTargetProfile_EmptyTenantID(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: ""
    identity: "user1"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "missing or empty id") {
		t.Fatalf("expected empty tenant id rejection, got: %v", err)
	}
}

// 20. TestTargetProfile_InvalidCredentialEnvName
func TestTargetProfile_InvalidCredentialEnvName(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    credential_env: "INVALID-ENV-VAR-WITH-DASHES"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "invalid credential_env variable name") {
		t.Fatalf("expected invalid credential_env name rejection, got: %v", err)
	}
}

// 21. TestTargetProfile_UnknownTopLevelField
func TestTargetProfile_UnknownTopLevelField(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
unrecognized_root_key: "danger"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unknown top-level field") {
		t.Fatalf("expected unknown top-level field rejection, got: %v", err)
	}
}

// 22. TestTargetProfile_UnknownSectionField
func TestTargetProfile_UnknownSectionField(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
  unexpected_target_option: true
safety:
  mode: "non_destructive"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field rejection in target section, got: %v", err)
	}
}

// 23. TestTargetProfile_Comparison_UnknownTenant
func TestTargetProfile_Comparison_UnknownTenant(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    resource_ids: ["r1"]
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "ghost_tenant"
      resource_owner_tenant: "t1"
      resource_id: "r1"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "unknown requester_tenant") {
		t.Fatalf("expected unknown requester_tenant rejection, got: %v", err)
	}
}

// 24. TestTargetProfile_Comparison_SelfComparison
func TestTargetProfile_Comparison_SelfComparison(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    resource_ids: ["r1"]
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "t1"
      resource_owner_tenant: "t1"
      resource_id: "r1"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "cannot be the same as resource_owner_tenant") {
		t.Fatalf("expected self-comparison rejection, got: %v", err)
	}
}

// 25. TestTargetProfile_Comparison_UnownedResource
func TestTargetProfile_Comparison_UnownedResource(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    resource_ids: ["r1"]
  - id: "t2"
    resource_ids: ["r2"]
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "t1"
      resource_owner_tenant: "t2"
      resource_id: "unowned_resource_999"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "not owned by or declared in resource_owner_tenant") {
		t.Fatalf("expected unowned resource rejection, got: %v", err)
	}
}

// 26. TestTargetProfile_Comparison_DuplicateComparison
func TestTargetProfile_Comparison_DuplicateComparison(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    resource_ids: ["r1"]
  - id: "t2"
    resource_ids: ["r2"]
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "t1"
      resource_owner_tenant: "t2"
      resource_id: "r2"
    - requester_tenant: "t1"
      resource_owner_tenant: "t2"
      resource_id: "r2"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "duplicate comparison definition") {
		t.Fatalf("expected duplicate comparison rejection, got: %v", err)
	}
}

// 27. TestTargetProfile_Comparison_MutatingMethod
func TestTargetProfile_Comparison_MutatingMethod(t *testing.T) {
	yamlStr := `version: 1
target:
  base_urls: ["http://127.0.0.1"]
safety:
  mode: "non_destructive"
tenants:
  - id: "t1"
    resource_ids: ["r1"]
  - id: "t2"
    resource_ids: ["r2"]
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "t1"
      resource_owner_tenant: "t2"
      resource_id: "r2"
      method: "DELETE"
`
	_, err := ParseTargetProfile([]byte(yamlStr))
	if err == nil || !strings.Contains(err.Error(), "mutating method") {
		t.Fatalf("expected mutating method in comparison rejection, got: %v", err)
	}
}

// 28. TestMultiTenantEngine_DualOptIn_Enforcement:
// Verifies that both profile authorization AND CLI opt-in are strictly required.
func TestMultiTenantEngine_DualOptIn_Enforcement(t *testing.T) {
	baseProfile := func(profileAllow bool) *TargetProfile {
		return &TargetProfile{
			Version: 1,
			Target: TargetConfig{
				BaseURLs:     []string{"http://127.0.0.1:8080"},
				AllowedHosts: []string{"127.0.0.1"},
			},
			Safety: SafetyConfig{
				Mode:                   "non_destructive",
				AllowCrossTenantChecks: profileAllow,
				MaxRequests:            10,
				RequestsPerSecond:      10,
				TimeoutSeconds:         2,
			},
			Tenants: []TenantConfig{
				{ID: "tA", ResourceIDs: []string{"resA"}},
				{ID: "tB", ResourceIDs: []string{"resB"}},
			},
			CrossTenantTests: CrossTenantTestsConfig{
				Enabled: profileAllow,
				Comparisons: []TenantComparison{
					{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "resB"},
				},
			},
		}
	}

	ctx := context.Background()

	// Case A: Profile false, CLI false -> Skipped
	{
		engine := NewMultiTenantEngine(baseProfile(false), MultiTenantEngineOptions{CLIOptIn: false})
		rep := engine.RunCrossTenantChecks(ctx)
		if rep.TotalExecuted != 0 || rep.TotalSkipped != 1 {
			t.Errorf("Case A: expected 0 executed, 1 skipped; got executed=%d, skipped=%d", rep.TotalExecuted, rep.TotalSkipped)
		}
	}

	// Case B: Profile true, CLI false -> Skipped (Gate 1 blocks)
	{
		engine := NewMultiTenantEngine(baseProfile(true), MultiTenantEngineOptions{CLIOptIn: false})
		rep := engine.RunCrossTenantChecks(ctx)
		if rep.TotalExecuted != 0 || rep.TotalSkipped != 1 {
			t.Errorf("Case B: expected 0 executed, 1 skipped; got executed=%d, skipped=%d", rep.TotalExecuted, rep.TotalSkipped)
		}
		if len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "--cross-tenant") {
			t.Errorf("Case B: expected CLI opt-in warning, got: %v", rep.Warnings)
		}
	}

	// Case C: Profile false, CLI true -> Skipped (Gate 2 blocks)
	{
		engine := NewMultiTenantEngine(baseProfile(false), MultiTenantEngineOptions{CLIOptIn: true})
		rep := engine.RunCrossTenantChecks(ctx)
		if rep.TotalExecuted != 0 || rep.TotalSkipped != 1 {
			t.Errorf("Case C: expected 0 executed, 1 skipped; got executed=%d, skipped=%d", rep.TotalExecuted, rep.TotalSkipped)
		}
		if len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "disabled in profile") {
			t.Errorf("Case C: expected profile policy warning, got: %v", rep.Warnings)
		}
	}
}

// 29. TestMultiTenantEngine_CredentialIsolationAndMissingEnv
func TestMultiTenantEngine_CredentialIsolationAndMissingEnv(t *testing.T) {
	envVarName := "FELIX_UNIT_TEST_ISOLATION_SECRET"
	_ = os.Unsetenv(envVarName)

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{"http://127.0.0.1:8080"},
			AllowedHosts: []string{"127.0.0.1"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            10,
			RequestsPerSecond:      10,
			TimeoutSeconds:         2,
		},
		Tenants: []TenantConfig{
			{ID: "tA", CredentialEnv: envVarName, ResourceIDs: []string{"resA"}},
			{ID: "tB", ResourceIDs: []string{"resB"}},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "resB"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{CLIOptIn: true})
	rep := engine.RunCrossTenantChecks(context.Background())

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	res := rep.Results[0]
	if res.Classification != CrossTenantMissingCredential {
		t.Errorf("expected MISSING_CREDENTIAL classification, got %s", res.Classification)
	}
	if !strings.Contains(res.Rationale, envVarName) {
		t.Errorf("expected rationale mentioning missing env var %s, got %s", envVarName, res.Rationale)
	}
}

// 30. TestMultiTenantEngine_ClassificationAndFalsePositiveDefense
// Comprehensive mock server testing all status codes, SPA false positive defenses, markers, and BOLA.
func TestMultiTenantEngine_ClassificationAndFalsePositiveDefense(t *testing.T) {
	t.Setenv("FELIX_TEST_TOKEN_A", "valid-canary-token-alpha")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "auth_401"):
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))

		case strings.Contains(path, "denied_403"):
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "forbidden"}`))

		case strings.Contains(path, "notfound_404"):
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "not found"}`))

		case strings.Contains(path, "ratelimit_429"):
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "too many requests"}`))

		case strings.Contains(path, "servererr_500"):
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal error"}`))

		case strings.Contains(path, "spa_shell_200"):
			// Generic SPA index.html returned with 200 OK
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div></body></html>`))

		case strings.Contains(path, "html_login_200"):
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h2>Please Sign In</h2><form><input type="password"/></form></body></html>`))

		case strings.Contains(path, "marker_match_200"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok", "content": "CONFIDENTIAL_PAYLOAD_OWNER_B"}`))

		case strings.Contains(path, "json_id_match_200"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"resource_id": "res_beta_json", "data": "secret"}`))

		case strings.Contains(path, "json_no_id_200"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success", "info": "generic message"}`))

		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`OK`))
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	host := u.Hostname()

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{ts.URL},
			AllowedHosts: []string{host, "127.0.0.1"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            100,
			RequestsPerSecond:      50,
			TimeoutSeconds:         5,
		},
		Tenants: []TenantConfig{
			{ID: "tA", CredentialEnv: "FELIX_TEST_TOKEN_A", ResourceIDs: []string{"resA"}},
			{
				ID: "tB",
				ResourceIDs: []string{
					"res_auth_401", "res_denied_403", "res_notfound_404",
					"res_ratelimit_429", "res_servererr_500", "res_spa_shell_200",
					"res_html_login_200", "res_marker_200", "res_beta_json", "res_json_no_id",
				},
			},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_auth_401", Path: "/api/auth_401"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_denied_403", Path: "/api/denied_403"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_notfound_404", Path: "/api/notfound_404"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_ratelimit_429", Path: "/api/ratelimit_429"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_servererr_500", Path: "/api/servererr_500"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_spa_shell_200", Path: "/api/spa_shell_200"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_html_login_200", Path: "/api/html_login_200"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_marker_200", Path: "/api/marker_match_200", ExpectedMarker: "CONFIDENTIAL_PAYLOAD_OWNER_B"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_beta_json", Path: "/api/json_id_match_200"},
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "res_json_no_id", Path: "/api/json_no_id_200"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{
		CLIOptIn:        true,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})

	rep := engine.RunCrossTenantChecks(context.Background())

	if rep.TotalExecuted != 10 {
		t.Fatalf("expected 10 executed probes, got %d", rep.TotalExecuted)
	}

	resultMap := make(map[string]CrossTenantResult)
	for _, r := range rep.Results {
		resultMap[r.ResourceID] = r
	}

	// 1. 401 -> AUTHENTICATION_REQUIRED
	if r := resultMap["res_auth_401"]; r.Classification != CrossTenantAuthenticationRequired {
		t.Errorf("401 test: expected AUTHENTICATION_REQUIRED, got %s", r.Classification)
	}

	// 2. 403 -> ACCESS_DENIED_OBSERVED (IsBOLAObserved: false)
	if r := resultMap["res_denied_403"]; r.Classification != CrossTenantAccessDeniedObserved || r.IsBOLAObserved {
		t.Errorf("403 test: expected ACCESS_DENIED_OBSERVED (no BOLA), got %s (bola=%t)", r.Classification, r.IsBOLAObserved)
	}

	// 3. 404 -> NOT_FOUND_OBSERVED (IsBOLAObserved: false)
	if r := resultMap["res_notfound_404"]; r.Classification != CrossTenantNotFoundObserved || r.IsBOLAObserved {
		t.Errorf("404 test: expected NOT_FOUND_OBSERVED (no BOLA), got %s (bola=%t)", r.Classification, r.IsBOLAObserved)
	}

	// 4. 429 -> RATE_LIMITED
	if r := resultMap["res_ratelimit_429"]; r.Classification != CrossTenantRateLimited {
		t.Errorf("429 test: expected RATE_LIMITED, got %s", r.Classification)
	}

	// 5. 500 -> TRANSPORT_FAILURE
	if r := resultMap["res_servererr_500"]; r.Classification != CrossTenantTransportFailure {
		t.Errorf("500 test: expected TRANSPORT_FAILURE, got %s", r.Classification)
	}

	// 6. SPA HTML shell 200 -> INCONCLUSIVE (CRITICAL FALSE-POSITIVE DEFENSE)
	if r := resultMap["res_spa_shell_200"]; r.Classification != CrossTenantInconclusive || r.IsBOLAObserved {
		t.Errorf("SPA shell test: expected INCONCLUSIVE (no BOLA), got %s (bola=%t)", r.Classification, r.IsBOLAObserved)
	}

	// 7. HTML login page 200 -> INCONCLUSIVE
	if r := resultMap["res_html_login_200"]; r.Classification != CrossTenantInconclusive || r.IsBOLAObserved {
		t.Errorf("HTML login test: expected INCONCLUSIVE (no BOLA), got %s (bola=%t)", r.Classification, r.IsBOLAObserved)
	}

	// 8. Expected marker match -> CROSS_TENANT_ACCESS_OBSERVED (BOLA TRUE, HIGH confidence)
	if r := resultMap["res_marker_200"]; r.Classification != CrossTenantAccessObserved || !r.IsBOLAObserved || r.Confidence != "HIGH" {
		t.Errorf("Marker match test: expected CROSS_TENANT_ACCESS_OBSERVED / BOLA=true / HIGH, got %s (bola=%t, conf=%s)", r.Classification, r.IsBOLAObserved, r.Confidence)
	}

	// 9. JSON resource ID match -> CROSS_TENANT_ACCESS_OBSERVED (BOLA TRUE, MEDIUM confidence)
	if r := resultMap["res_beta_json"]; r.Classification != CrossTenantAccessObserved || !r.IsBOLAObserved || r.Confidence != "MEDIUM" {
		t.Errorf("JSON ID match test: expected CROSS_TENANT_ACCESS_OBSERVED / BOLA=true / MEDIUM, got %s (bola=%t, conf=%s)", r.Classification, r.IsBOLAObserved, r.Confidence)
	}

	// 10. Generic JSON without ID -> INCONCLUSIVE
	if r := resultMap["res_json_no_id"]; r.Classification != CrossTenantInconclusive || r.IsBOLAObserved {
		t.Errorf("Generic JSON test: expected INCONCLUSIVE, got %s (bola=%t)", r.Classification, r.IsBOLAObserved)
	}
}

// 31. TestMultiTenantEngine_ScopeAndMutatingProtection verifies that SSRF, unallowed hosts,
// and mutating path segments are skipped or blocked before dispatch.
func TestMultiTenantEngine_ScopeAndMutatingProtection(t *testing.T) {
	t.Setenv("FELIX_SCOPE_TOKEN", "valid-scope-test-token")

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{"http://authorized.example.com"},
			AllowedHosts: []string{"authorized.example.com"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            10,
			RequestsPerSecond:      10,
			TimeoutSeconds:         2,
		},
		Tenants: []TenantConfig{
			{ID: "tA", CredentialEnv: "FELIX_SCOPE_TOKEN", ResourceIDs: []string{"resA"}},
			{ID: "tB", ResourceIDs: []string{"resB1", "resB2"}},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				// Comparison 1: Mutating keyword in path (/delete/)
				{RequesterTenant: "tA", ResourceOwnerTenant: "tB", ResourceID: "resB1", Path: "/api/v1/delete/{id}"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{CLIOptIn: true})
	rep := engine.RunCrossTenantChecks(context.Background())

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	if rep.Results[0].Classification != CrossTenantUnsafeRouteSkipped {
		t.Errorf("expected UNSAFE_ROUTE_SKIPPED for mutating keyword path, got %s", rep.Results[0].Classification)
	}
}

// 32. TestMultiTenantEngine_AdversarialBOLAPredicates tests subtle false-positive scenarios:
// echoed resource IDs in error payloads, reflected query filters, unrelated fields,
// misleading error strings containing markers, and authentic BOLA.
func TestMultiTenantEngine_AdversarialBOLAPredicates(t *testing.T) {
	t.Setenv("FELIX_ADVERSARIAL_TOKEN", "token-adv-123")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(path, "echoed_error"):
			// Server echoes requested resource ID inside an error JSON
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "fail", "error": "Document not found", "requested_id": "res_doc_echo"}`))

		case strings.Contains(path, "reflected_filter"):
			// Server echoes query filter or resource ID with empty payload
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success", "filter": "res_doc_filter", "count": 0, "items": []}`))

		case strings.Contains(path, "rejected_payload"):
			// 200 OK wrapping application-level rejection
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": 403, "error": "Access denied for res_doc_rej", "tenant_access": "unauthorized"}`))

		case strings.Contains(path, "unrelated_field"):
			// Substring match in unrelated attribute
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"author_id": "res_doc_unrel_author", "notes": "No permissions to read"}`))

		case strings.Contains(path, "misleading_marker"):
			// Expected marker appears, but wrapped in an error/rejection message
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "error", "message": "Cannot access CONFIDENTIAL_ALPHA_DATA: permission denied"}`))

		case strings.Contains(path, "plain_unstructured"):
			// Plain text containing ID, but no valid JSON structure
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`Requested entity res_doc_plain was not resolved.`))

		case strings.Contains(path, "authentic_bola"):
			// Real BOLA: canonical resource ID and substantive data returned
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "res_doc_authentic", "title": "Quarterly Financial Secret", "owner": "tenant_owner", "data": "CONFIDENTIAL_ALPHA_DATA"}`))

		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	host := u.Hostname()

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{ts.URL},
			AllowedHosts: []string{host, "127.0.0.1"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            20,
			RequestsPerSecond:      20,
			TimeoutSeconds:         5,
		},
		Tenants: []TenantConfig{
			{ID: "tRequester", CredentialEnv: "FELIX_ADVERSARIAL_TOKEN", ResourceIDs: []string{"req_r1"}},
			{
				ID: "tOwner",
				ResourceIDs: []string{
					"res_doc_echo", "res_doc_filter", "res_doc_rej",
					"res_doc_unrel", "res_doc_marker_err", "res_doc_plain", "res_doc_authentic",
				},
			},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_echo", Path: "/api/echoed_error"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_filter", Path: "/api/reflected_filter"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_rej", Path: "/api/rejected_payload"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_unrel", Path: "/api/unrelated_field"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_marker_err", Path: "/api/misleading_marker", ExpectedMarker: "CONFIDENTIAL_ALPHA_DATA"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_plain", Path: "/api/plain_unstructured"},
				{RequesterTenant: "tRequester", ResourceOwnerTenant: "tOwner", ResourceID: "res_doc_authentic", Path: "/api/authentic_bola", ExpectedMarker: "CONFIDENTIAL_ALPHA_DATA"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{
		CLIOptIn:        true,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})

	rep := engine.RunCrossTenantChecks(context.Background())

	resMap := make(map[string]CrossTenantResult)
	for _, r := range rep.Results {
		resMap[r.ResourceID] = r
	}

	// 1. Echoed resource ID in error -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_echo"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Echoed error test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 2. Reflected filter in empty payload -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_filter"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Reflected filter test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 3. Rejected payload wrapped in 200 -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_rej"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Rejected payload test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 4. Unrelated field -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_unrel"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Unrelated field test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 5. Misleading marker inside error string -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_marker_err"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Misleading marker in error test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 6. Plain unstructured text -> MUST BE INCONCLUSIVE (NO BOLA)
	if r := resMap["res_doc_plain"]; r.IsBOLAObserved || r.Classification != CrossTenantInconclusive {
		t.Errorf("Plain unstructured text test: expected INCONCLUSIVE (BOLA=false), got classification=%s, bola=%t", r.Classification, r.IsBOLAObserved)
	}

	// 7. Authentic BOLA with canonical structure & marker -> MUST BE CROSS_TENANT_ACCESS_OBSERVED (BOLA=TRUE, HIGH confidence)
	if r := resMap["res_doc_authentic"]; !r.IsBOLAObserved || r.Classification != CrossTenantAccessObserved || r.Confidence != "HIGH" {
		t.Errorf("Authentic BOLA test: expected CROSS_TENANT_ACCESS_OBSERVED, BOLA=true, HIGH; got classification=%s, bola=%t, conf=%s", r.Classification, r.IsBOLAObserved, r.Confidence)
	}
}

// 33. TestMultiTenantEngine_CanaryCredentialIsolation verifies that canary credentials
// are used strictly for their designated tenant, custom headers cannot override Authorization,
// and raw tokens never leak into evidence snippets.
func TestMultiTenantEngine_CanaryCredentialIsolation(t *testing.T) {
	canaryToken := "SUPER_CONFIDENTIAL_CANARY_JWT_98765"
	t.Setenv("FELIX_CANARY_ISOLATION_ENV", canaryToken)

	var receivedAuthHeader string
	var receivedCustomHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedCustomHeader = r.Header.Get("X-Audit-Tenant")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Server echoes the canary token to verify redactor strips it
		w.Write([]byte(fmt.Sprintf(`{"status": "ok", "echo_token": "%s", "data": "payload"}`, canaryToken)))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	host := u.Hostname()

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{ts.URL},
			AllowedHosts: []string{host, "127.0.0.1"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            10,
			RequestsPerSecond:      10,
			TimeoutSeconds:         5,
		},
		Tenants: []TenantConfig{
			{
				ID:            "tAlpha",
				CredentialEnv: "FELIX_CANARY_ISOLATION_ENV",
				Headers: map[string]string{
					"Authorization":  "Bearer ATTACKER_OVERRIDE_TOKEN", // should be strictly ignored!
					"X-Audit-Tenant": "Alpha-Corp",
				},
				ResourceIDs: []string{"resA"},
			},
			{ID: "tBeta", ResourceIDs: []string{"resB"}},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				{RequesterTenant: "tAlpha", ResourceOwnerTenant: "tBeta", ResourceID: "resB", Path: "/api/check"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{
		CLIOptIn:        true,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})

	rep := engine.RunCrossTenantChecks(context.Background())

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rep.Results))
	}
	res := rep.Results[0]

	// 1. Verify outbound Authorization header contains the canary token, not the override
	expectedAuth := "Bearer " + canaryToken
	if receivedAuthHeader != expectedAuth {
		t.Errorf("expected Authorization header %q, got %q", expectedAuth, receivedAuthHeader)
	}

	// 2. Verify custom non-auth headers are passed
	if receivedCustomHeader != "Alpha-Corp" {
		t.Errorf("expected X-Audit-Tenant header 'Alpha-Corp', got %q", receivedCustomHeader)
	}

	// 3. Verify canary token is redacted from EvidenceSnippet
	if strings.Contains(res.EvidenceSnippet, canaryToken) {
		t.Errorf("raw canary token leaked in EvidenceSnippet: %s", res.EvidenceSnippet)
	}
	if !strings.Contains(res.EvidenceSnippet, "[REDACTED]") && !strings.Contains(res.EvidenceSnippet, "[REDACTED_CANARY_TOKEN]") {
		t.Errorf("expected redaction marker in EvidenceSnippet: %s", res.EvidenceSnippet)
	}
}

// 34. TestMultiTenantEngine_SSRFAndScopeBoundaries verifies complete request path enforcement:
// embedded credentials, unallowed hosts, mutating query parameters, mutating methods, and redirect handling.
func TestMultiTenantEngine_SSRFAndScopeBoundaries(t *testing.T) {
	t.Setenv("FELIX_SSRF_TOKEN", "test-token")

	p := &TargetProfile{
		Version: 1,
		Target: TargetConfig{
			BaseURLs:     []string{"http://authorized-scope.example.com"},
			AllowedHosts: []string{"authorized-scope.example.com"},
		},
		Safety: SafetyConfig{
			Mode:                   "non_destructive",
			AllowCrossTenantChecks: true,
			MaxRequests:            20,
			RequestsPerSecond:      10,
			TimeoutSeconds:         2,
			FollowRedirects:        false,
		},
		Tenants: []TenantConfig{
			{ID: "t1", CredentialEnv: "FELIX_SSRF_TOKEN", ResourceIDs: []string{"r1"}},
			{ID: "t2", ResourceIDs: []string{"r_embedded_user", "r_mut_query", "r_mut_method", "r_unallowed_host"}},
		},
		CrossTenantTests: CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []TenantComparison{
				// Embedded credentials in path
				{RequesterTenant: "t1", ResourceOwnerTenant: "t2", ResourceID: "r_embedded_user", Path: "http://user:pass@authorized-scope.example.com/api/r"},
				// Mutating query parameter
				{RequesterTenant: "t1", ResourceOwnerTenant: "t2", ResourceID: "r_mut_query", Path: "/api/items?action=delete&target=all"},
				// Mutating method
				{RequesterTenant: "t1", ResourceOwnerTenant: "t2", ResourceID: "r_mut_method", Path: "/api/items", Method: "DELETE"},
			},
		},
	}

	engine := NewMultiTenantEngine(p, MultiTenantEngineOptions{CLIOptIn: true})
	rep := engine.RunCrossTenantChecks(context.Background())

	resMap := make(map[string]CrossTenantResult)
	for _, r := range rep.Results {
		resMap[r.ResourceID] = r
	}

	// 1. Embedded credentials -> SCOPE_BLOCKED
	if r := resMap["r_embedded_user"]; r.Classification != CrossTenantScopeBlocked {
		t.Errorf("Embedded userinfo: expected SCOPE_BLOCKED, got %s", r.Classification)
	}

	// 2. Mutating query parameter -> UNSAFE_ROUTE_SKIPPED
	if r := resMap["r_mut_query"]; r.Classification != CrossTenantUnsafeRouteSkipped {
		t.Errorf("Mutating query: expected UNSAFE_ROUTE_SKIPPED, got %s", r.Classification)
	}

	// 3. Mutating method -> UNSAFE_ROUTE_SKIPPED
	if r := resMap["r_mut_method"]; r.Classification != CrossTenantUnsafeRouteSkipped {
		t.Errorf("Mutating method: expected UNSAFE_ROUTE_SKIPPED, got %s", r.Classification)
	}
}
