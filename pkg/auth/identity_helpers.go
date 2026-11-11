package auth

import (
	"net"
	"net/url"
	"strings"
)

// HasIdentity reports whether the given identity context is configured and usable.
// IdentityUnauthenticated is available whenever the IdentityManager is initialized.
// Authenticated identities require at least one configured credential (bearer token, custom header, or cookies).
func (m *IdentityManager) HasIdentity(id IdentityContext) bool {
	if m == nil {
		return false
	}
	if id == IdentityUnauthenticated {
		return true
	}
	tr := m.Transport()
	if tr == nil {
		return false
	}
	cred, ok := tr.GetIdentityCredential(id)
	if !ok || cred == nil {
		return false
	}
	return cred.BearerToken != "" || (cred.HeaderName != "" && cred.HeaderValue != "") || len(cred.Cookies) > 0
}

// ConfiguredIdentities returns all configured identities in deterministic evaluation order,
// always starting with IdentityUnauthenticated followed by configured authenticated identities.
func (m *IdentityManager) ConfiguredIdentities() []IdentityContext {
	if m == nil {
		return nil
	}
	order := []IdentityContext{
		IdentityUnauthenticated,
		IdentityUserA,
		IdentityUserB,
		IdentityAdmin,
	}
	var out []IdentityContext
	for _, id := range order {
		if m.HasIdentity(id) {
			out = append(out, id)
		}
	}
	return out
}

// ConfiguredAuthenticatedIdentities returns all configured authenticated identities (excluding anonymous).
func (m *IdentityManager) ConfiguredAuthenticatedIdentities() []IdentityContext {
	if m == nil {
		return nil
	}
	order := []IdentityContext{
		IdentityUserA,
		IdentityUserB,
		IdentityAdmin,
	}
	var out []IdentityContext
	for _, id := range order {
		if m.HasIdentity(id) {
			out = append(out, id)
		}
	}
	return out
}

// IdentityCredentialSummary returns a secret-redacted metadata summary for an identity if configured.
func (m *IdentityManager) IdentityCredentialSummary(id IdentityContext) (IdentityCredentialSummary, bool) {
	if m == nil || m.Transport() == nil {
		return IdentityCredentialSummary{}, false
	}
	cred, ok := m.Transport().GetIdentityCredential(id)
	if !ok || cred == nil {
		return IdentityCredentialSummary{}, false
	}
	return cred.Summary(), true
}

// IdentityRole returns the declared role for the given identity context.
func (m *IdentityManager) IdentityRole(id IdentityContext) PersonaRole {
	if m != nil && m.Transport() != nil {
		if cred, ok := m.Transport().GetIdentityCredential(id); ok && cred != nil && cred.Role != "" {
			return cred.Role
		}
	}
	switch id {
	case IdentityAdmin:
		return RoleAdmin
	case IdentityUserA:
		return RoleVictim
	case IdentityUserB:
		return RoleAttacker
	default:
		return RoleAnonymous
	}
}

// IdentityUsername returns the configured username metadata for the identity context, if present.
func (m *IdentityManager) IdentityUsername(id IdentityContext) string {
	if m != nil && m.Transport() != nil {
		if cred, ok := m.Transport().GetIdentityCredential(id); ok && cred != nil {
			return cred.Username
		}
	}
	return ""
}

// AreCredentialsDistinct checks whether two configured identities actually hold distinct credentials
// without exposing any secret values.
func (m *IdentityManager) AreCredentialsDistinct(a, b IdentityContext) bool {
	if a == b {
		return false
	}
	if a == IdentityUnauthenticated || b == IdentityUnauthenticated {
		return m.HasIdentity(a) && m.HasIdentity(b)
	}
	if m == nil || m.Transport() == nil {
		return false
	}
	credA, okA := m.Transport().GetIdentityCredential(a)
	credB, okB := m.Transport().GetIdentityCredential(b)
	if !okA || !okB || credA == nil || credB == nil {
		return false
	}
	if credA.BearerToken != "" || credB.BearerToken != "" {
		return credA.BearerToken != credB.BearerToken
	}
	if len(credA.Cookies) > 0 || len(credB.Cookies) > 0 {
		if len(credA.Cookies) != len(credB.Cookies) {
			return true
		}
		mapB := make(map[string]string, len(credB.Cookies))
		for _, c := range credB.Cookies {
			if c != nil {
				mapB[c.Name] = c.Value
			}
		}
		for _, c := range credA.Cookies {
			if c == nil {
				continue
			}
			if bv, ok := mapB[c.Name]; !ok || bv != c.Value {
				return true
			}
		}
		return false
	}
	if credA.HeaderName != "" || credB.HeaderName != "" {
		return !(credA.HeaderName == credB.HeaderName && credA.HeaderValue == credB.HeaderValue)
	}
	if len(credA.CustomHeaders) > 0 || len(credB.CustomHeaders) > 0 {
		if len(credA.CustomHeaders) != len(credB.CustomHeaders) {
			return true
		}
		for k, v := range credA.CustomHeaders {
			if bv, ok := credB.CustomHeaders[k]; !ok || bv != v {
				return true
			}
		}
		return false
	}
	return false
}

// IsLoopbackHost reports whether host is a local loopback hostname or IP address.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "ip6-localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// MatchAuthorizedFixtureHost checks whether hostname/hostPort matches an explicit fixture entry.
func MatchAuthorizedFixtureHost(hostname, hostPort, entry string) bool {
	clean := strings.ToLower(strings.TrimSpace(entry))
	if clean == "" {
		return false
	}
	if strings.Contains(clean, "://") {
		if parsedAF, err := url.Parse(clean); err == nil && parsedAF.Hostname() != "" {
			if parsedAF.Port() != "" {
				return strings.EqualFold(hostPort, strings.ToLower(parsedAF.Host))
			}
			return strings.EqualFold(hostname, strings.ToLower(parsedAF.Hostname()))
		}
	}
	if strings.HasPrefix(clean, "*.") {
		return strings.HasSuffix(hostname, clean[1:])
	}
	if (strings.HasPrefix(clean, "[") && strings.Contains(clean, "]:")) || (!strings.HasPrefix(clean, "[") && strings.Contains(clean, ":")) {
		return strings.EqualFold(hostPort, clean)
	}
	return strings.EqualFold(hostname, clean)
}

// IsIsolatedFixtureTarget determines whether rawURL resolves to an explicitly verified fixture
// or isolated loopback host, rejecting generic internal/local/production domains by default.
func IsIsolatedFixtureTarget(rawURL string, authorizedFixtures []string, isFixtureFunc func(string) bool) bool {
	if isFixtureFunc != nil {
		return isFixtureFunc(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	hostPort := strings.ToLower(strings.TrimSpace(u.Host))
	if hostname == "" {
		return false
	}

	if len(authorizedFixtures) > 0 {
		for _, af := range authorizedFixtures {
			if MatchAuthorizedFixtureHost(hostname, hostPort, af) {
				return true
			}
		}
		return false
	}

	return IsLoopbackHost(hostname)
}
