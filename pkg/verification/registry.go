package verification

import (
	"felix/pkg/report"
)

// PolicyRegistry stores and resolves verification policies.
type PolicyRegistry struct {
	policies []Policy
	fallback Policy
}

// NewDefaultRegistry constructs a registry pre-loaded with all standard Stage 11 policies.
func NewDefaultRegistry() *PolicyRegistry {
	r := &PolicyRegistry{
		fallback: NewGenericPolicy(),
	}

	// Register policies in specific order (specific policies first, generic last)
	r.Register(NewDiscoveryExposurePolicy())
	r.Register(NewAuthenticationPolicy())
	r.Register(NewAuthorizationPolicy())
	r.Register(NewAPISecurityPolicy())
	r.Register(NewWebVulnerabilityPolicy())
	r.Register(NewCloudSecurityPolicy())
	r.Register(NewBusinessLogicPolicy())

	return r
}

// Register appends a policy to the registry.
func (pr *PolicyRegistry) Register(p Policy) {
	pr.policies = append(pr.policies, p)
}

// Resolve identifies the best matching policy for a given finding.
func (pr *PolicyRegistry) Resolve(f report.Finding) Policy {
	for _, p := range pr.policies {
		if p.AppliesTo(f) {
			return p
		}
	}
	return pr.fallback
}

// ListPolicies returns all currently registered policies.
func (pr *PolicyRegistry) ListPolicies() []Policy {
	res := make([]Policy, len(pr.policies)+1)
	copy(res, pr.policies)
	res[len(res)-1] = pr.fallback
	return res
}
