package authz

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Planner generates concrete authorization test cases based on an AuthzPolicy and target endpoints.
type Planner struct {
	policy *AuthzPolicy
}

// NewPlanner creates a test planner for a given authorization policy.
func NewPlanner(policy *AuthzPolicy) *Planner {
	return &Planner{policy: policy}
}

// PlanTestCases generates the complete matrix of authorization test cases.
func (p *Planner) PlanTestCases(baseURL string) []AuthzTestCase {
	var cases []AuthzTestCase
	baseURL = strings.TrimRight(baseURL, "/")

	// 1. Plan BOLA & Horizontal Escalation Test Cases
	cases = append(cases, p.planBOLATests(baseURL)...)

	// 2. Plan BFLA & Vertical Function Escalation Test Cases
	cases = append(cases, p.planBFLATests(baseURL)...)

	// 3. Plan BOPLA (Property Exposure & Property Modification) Test Cases
	cases = append(cases, p.planBOPLATests(baseURL)...)

	return cases
}

func (p *Planner) planBOLATests(baseURL string) []AuthzTestCase {
	var cases []AuthzTestCase

	for resID, res := range p.policy.Resources {
		owner := res.OwnerAlias
		if owner == "" {
			continue
		}

		// Find resource endpoint pattern from endpoints list or fallback to standard REST route
		endpointTemplate := fmt.Sprintf("/api/%ss/%s", res.Type, resID)
		for _, ep := range p.policy.Endpoints {
			if strings.Contains(ep.Pattern, "{id}") || strings.Contains(ep.Pattern, res.Type) {
				endpointTemplate = strings.Replace(ep.Pattern, "{id}", resID, -1)
				break
			}
		}
		targetURL := baseURL + endpointTemplate

		// Baseline Case: Owner accesses their own resource -> Expected ALLOW
		cases = append(cases, AuthzTestCase{
			ID:               uuid.New().String(),
			Category:         CategoryBOLA,
			Endpoint:         targetURL,
			Method:           "GET",
			PrimaryIdentity:  owner,
			BaselineIdentity: owner,
			TargetResource:   resID,
			ExpectedResult:   ExpectedAllow,
			Description:      fmt.Sprintf("Baseline: Owner %q accesses own %s %q", owner, res.Type, resID),
		})

		// Cross-Identity Cases: Other identities attempt to access the resource
		for otherAlias, otherID := range p.policy.Identities {
			if otherAlias == owner {
				continue
			}

			// Check if resource is intentionally shared
			isSharedWithOther := false
			if res.IsShared {
				for _, allowed := range res.AllowedIdentities {
					if allowed == otherAlias {
						isSharedWithOther = true
						break
					}
				}
			}

			if isSharedWithOther {
				// Shared resource test case: Expected ALLOW
				cases = append(cases, AuthzTestCase{
					ID:               uuid.New().String(),
					Category:         CategoryBOLA,
					Endpoint:         targetURL,
					Method:           "GET",
					PrimaryIdentity:  otherAlias,
					BaselineIdentity: owner,
					TargetResource:   resID,
					ExpectedResult:   ExpectedAllow,
					Description:      fmt.Sprintf("Legitimately shared resource: %q accesses shared %s %q", otherAlias, res.Type, resID),
				})
			} else {
				// Unauthorized cross-user BOLA test case: Expected DENY
				cat := CategoryBOLA
				if otherID.PrivilegeLevel == p.policy.Identities[owner].PrivilegeLevel {
					// Also flags Horizontal Escalation
					cat = CategoryBOLA
				}

				cases = append(cases, AuthzTestCase{
					ID:               uuid.New().String(),
					Category:         cat,
					Endpoint:         targetURL,
					Method:           "GET",
					PrimaryIdentity:  otherAlias,
					BaselineIdentity: owner,
					TargetResource:   resID,
					ExpectedResult:   ExpectedDeny,
					Description:      fmt.Sprintf("Cross-user object access: %q attempts to access %q's %s %q", otherAlias, owner, res.Type, resID),
				})

				// Cross-Tenant Boundary Case: If tenants differ, flag tenant isolation
				if res.TenantID != "" && otherID.TenantID != "" && res.TenantID != otherID.TenantID {
					cases = append(cases, AuthzTestCase{
						ID:               uuid.New().String(),
						Category:         CategoryHorizontalEsc,
						Endpoint:         targetURL,
						Method:           "GET",
						PrimaryIdentity:  otherAlias,
						BaselineIdentity: owner,
						TargetResource:   resID,
						ExpectedResult:   ExpectedDeny,
						Description:      fmt.Sprintf("Cross-tenant access: %q (tenant %q) attempts to access %q's resource in tenant %q", otherAlias, otherID.TenantID, resID, res.TenantID),
					})
				}
			}
		}
	}

	return cases
}

func (p *Planner) planBFLATests(baseURL string) []AuthzTestCase {
	var cases []AuthzTestCase

	for _, ep := range p.policy.Endpoints {
		if !ep.AdminOnly && len(ep.DeniedRoles) == 0 {
			continue
		}

		targetURL := baseURL + ep.Pattern

		// Find an administrator / authorized identity
		var adminAlias string
		for alias, id := range p.policy.Identities {
			if id.Role == "admin" || id.PrivilegeLevel >= 5 {
				adminAlias = alias
				break
			}
		}

		// Find unprivileged / denied identities
		for alias, id := range p.policy.Identities {
			if id.Role == "admin" || id.PrivilegeLevel >= 5 {
				continue
			}

			// Check if role is explicitly allowed or denied
			isDenied := ep.AdminOnly
			for _, dr := range ep.DeniedRoles {
				if strings.EqualFold(dr, id.Role) {
					isDenied = true
					break
				}
			}

			if isDenied {
				// BFLA test: Unprivileged identity calls administrative endpoint
				cases = append(cases, AuthzTestCase{
					ID:               uuid.New().String(),
					Category:         CategoryBFLA,
					Endpoint:         targetURL,
					Method:           ep.Method,
					PrimaryIdentity:  alias,
					BaselineIdentity: adminAlias,
					ExpectedResult:   ExpectedDeny,
					Description:      fmt.Sprintf("Function-level access: %q (role %q) invokes restricted endpoint %s %s", alias, id.Role, ep.Method, ep.Pattern),
				})
			}
		}
	}

	return cases
}

func (p *Planner) planBOPLATests(baseURL string) []AuthzTestCase {
	var cases []AuthzTestCase

	// 1. BOPLA Property Exposure Tests (Read operations)
	for resID, res := range p.policy.Resources {
		if len(res.SensitiveProperties) == 0 {
			continue
		}

		endpoint := baseURL + fmt.Sprintf("/api/%ss/%s", res.Type, resID)
		for otherAlias, otherID := range p.policy.Identities {
			if otherAlias == res.OwnerAlias || otherID.Role == "admin" {
				continue
			}

			for _, prop := range res.SensitiveProperties {
				cases = append(cases, AuthzTestCase{
					ID:               uuid.New().String(),
					Category:         CategoryBOPLAExposure,
					Endpoint:         endpoint,
					Method:           "GET",
					PrimaryIdentity:  otherAlias,
					BaselineIdentity: res.OwnerAlias,
					TargetResource:   resID,
					PropertyKey:      prop,
					ExpectedResult:   ExpectedDeny,
					Description:      fmt.Sprintf("Property exposure: inspecting if sensitive property %q of %s %q is exposed to %q", prop, res.Type, resID, otherAlias),
				})
			}
		}
	}

	// 2. BOPLA Property Modification Tests (Write operations)
	for _, ep := range p.policy.Endpoints {
		if len(ep.MonitoredProperties) == 0 {
			continue
		}

		// Identify mutating methods (PUT, POST, PATCH)
		method := ep.Method
		if method != "PUT" && method != "POST" && method != "PATCH" {
			method = "PUT"
		}
		targetURL := baseURL + ep.Pattern

		for _, prop := range ep.MonitoredProperties {
			for alias, id := range p.policy.Identities {
				if id.Role == "admin" {
					continue
				}

				// Simulated mutation payload attempting privilege or state escalation
				var propVal string
				switch prop {
				case "role":
					propVal = "admin"
				case "is_admin":
					propVal = "true"
				case "price":
					propVal = "0.00"
				case "tenant_id":
					propVal = "tenant_foreign"
				case "owner":
					propVal = alias
				default:
					propVal = "escalated"
				}

				payload := fmt.Sprintf(`{"%s": "%s"}`, prop, propVal)
				if prop == "is_admin" {
					payload = `{"is_admin": true}`
				}

				cases = append(cases, AuthzTestCase{
					ID:               uuid.New().String(),
					Category:         CategoryBOPLAModification,
					Endpoint:         targetURL,
					Method:           method,
					PrimaryIdentity:  alias,
					PropertyKey:      prop,
					PropertyValue:    propVal,
					Payload:          payload,
					ExpectedResult:   ExpectedDeny,
					Description:      fmt.Sprintf("Property modification: %q attempts to modify protected property %q via %s %s", alias, prop, method, ep.Pattern),
				})
			}
		}
	}

	return cases
}
