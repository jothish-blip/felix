package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyFromFile_SamplePolicy(t *testing.T) {
	// Locate examples/authz_policy_sample.json relative to repository root
	path := filepath.Join("..", "..", "examples", "authz_policy_sample.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sample policy file not found at %s: %v", path, err)
	}

	policy, err := LoadPolicyFromFile(path)
	if err != nil {
		t.Fatalf("failed to load and parse sample policy: %v", err)
	}

	// 1. Validate policy invariants
	if err := policy.Validate(); err != nil {
		t.Fatalf("sample policy validation failed: %v", err)
	}

	// 2. Safety invariant: write tests must be disabled by default
	if policy.AllowWriteTests {
		t.Errorf("sample policy must enforce allow_write_tests: false for safety")
	}

	// 3. Verify identities structure
	expectedIdentities := []string{"user_a", "user_b", "admin"}
	for _, idAlias := range expectedIdentities {
		id, ok := policy.Identities[idAlias]
		if !ok {
			t.Errorf("expected identity %q in sample policy", idAlias)
			continue
		}
		if id.Role == "" {
			t.Errorf("identity %q must have a non-empty role", idAlias)
		}
		if id.TenantID == "" {
			t.Errorf("identity %q must have a non-empty tenant_id", idAlias)
		}
	}

	// 4. Verify resources structure and ownership
	expectedResources := []string{"doc_101", "doc_202"}
	for _, resID := range expectedResources {
		res, ok := policy.Resources[resID]
		if !ok {
			t.Errorf("expected resource %q in sample policy", resID)
			continue
		}
		if _, ownerOk := policy.Identities[res.OwnerAlias]; !ownerOk {
			t.Errorf("resource %q references unknown owner %q", resID, res.OwnerAlias)
		}
	}

	// 5. Verify endpoints structure
	if len(policy.Endpoints) < 2 {
		t.Errorf("expected at least 2 endpoint rules in sample policy, got %d", len(policy.Endpoints))
	}

	// 6. Test credential injection with environment variables
	os.Setenv("FELIX_AUTH_USER_A_TOKEN", "mock-token-user-a")
	defer os.Unsetenv("FELIX_AUTH_USER_A_TOKEN")

	InjectEnvCredentials(policy)
	authHeader := policy.Identities["user_a"].Headers["Authorization"]
	if authHeader != "Bearer mock-token-user-a" {
		t.Errorf("expected injected token in user_a Authorization header, got: %s", authHeader)
	}

	// 7. Verify SafeMetadata scrubbing
	safeMeta := policy.SafeMetadata()
	if strings.Contains(safeMeta, "mock-token-user-a") {
		t.Errorf("SafeMetadata() must redact injected auth tokens, got: %s", safeMeta)
	}
}

func TestPolicyValidation_InvalidCases(t *testing.T) {
	// Case 1: Empty identities
	p1 := &AuthzPolicy{
		Identities: map[string]TestIdentity{},
	}
	if err := p1.Validate(); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("expected error for empty identities, got: %v", err)
	}

	// Case 2: Identity with empty role
	p2 := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"user_a": {Alias: "user_a", Role: ""},
		},
	}
	if err := p2.Validate(); err == nil || !strings.Contains(err.Error(), "must define a role") {
		t.Errorf("expected error for empty identity role, got: %v", err)
	}

	// Case 3: Resource with unknown owner
	p3 := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"user_a": {Alias: "user_a", Role: "user"},
		},
		Resources: map[string]TestResource{
			"doc_1": {ID: "doc_1", OwnerAlias: "nonexistent"},
		},
	}
	if err := p3.Validate(); err == nil || !strings.Contains(err.Error(), "unknown owner") {
		t.Errorf("expected error for unknown resource owner, got: %v", err)
	}

	// Case 4: Endpoint with empty pattern
	p4 := &AuthzPolicy{
		Identities: map[string]TestIdentity{
			"user_a": {Alias: "user_a", Role: "user"},
		},
		Endpoints: []EndpointRule{
			{Pattern: "", Method: "GET"},
		},
	}
	if err := p4.Validate(); err == nil || !strings.Contains(err.Error(), "empty path pattern") {
		t.Errorf("expected error for empty endpoint pattern, got: %v", err)
	}
}
