package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadPolicyFromFile reads and parses an AuthzPolicy from a JSON file.
func LoadPolicyFromFile(filePath string) (*AuthzPolicy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", filePath, err)
	}
	return ParsePolicy(data)
}

// ParsePolicy decodes and validates an authorization policy.
func ParsePolicy(data []byte) (*AuthzPolicy, error) {
	var policy AuthzPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("invalid policy JSON format: %w", err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	return &policy, nil
}

// Validate ensures the policy has required fields and logical consistency.
func (p *AuthzPolicy) Validate() error {
	if len(p.Identities) < 1 {
		return errors.New("policy must define at least one test identity")
	}

	for alias, id := range p.Identities {
		if strings.TrimSpace(alias) == "" {
			return errors.New("identity alias cannot be empty")
		}
		if strings.TrimSpace(id.Role) == "" {
			return fmt.Errorf("identity %q must define a role", alias)
		}
	}

	for resID, res := range p.Resources {
		if strings.TrimSpace(resID) == "" {
			return errors.New("resource ID cannot be empty")
		}
		if res.OwnerAlias != "" {
			if _, exists := p.Identities[res.OwnerAlias]; !exists {
				return fmt.Errorf("resource %q references unknown owner identity %q", resID, res.OwnerAlias)
			}
		}
	}

	for i, ep := range p.Endpoints {
		if strings.TrimSpace(ep.Pattern) == "" {
			return fmt.Errorf("endpoint rule %d has empty path pattern", i)
		}
		if strings.TrimSpace(ep.Method) == "" {
			return fmt.Errorf("endpoint rule %d has empty HTTP method", i)
		}
	}

	return nil
}

// SafeMetadata returns a clean JSON representation of the policy with all credentials/headers omitted.
func (p *AuthzPolicy) SafeMetadata() string {
	safeIdentities := make(map[string]TestIdentity)
	for alias, id := range p.Identities {
		safeIdentities[alias] = TestIdentity{
			Alias:          id.Alias,
			Role:           id.Role,
			TenantID:       id.TenantID,
			PrivilegeLevel: id.PrivilegeLevel,
			Headers:        id.ScrubbedHeaders(),
			Cookies:        nil, // Never persist raw session cookies
		}
	}

	safePolicy := AuthzPolicy{
		AssessmentRef:    p.AssessmentRef,
		AuthorizationDoc: p.AuthorizationDoc,
		AllowWriteTests:  p.AllowWriteTests,
		Identities:       safeIdentities,
		Resources:        p.Resources,
		Endpoints:        p.Endpoints,
	}

	b, _ := json.Marshal(safePolicy)
	return string(b)
}
