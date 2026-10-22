package oast

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"felix/pkg/secrets"
)

var (
	nonGlobalCIDRs    []*net.IPNet
	cloudMetadataIPv4 = net.ParseIP("169.254.169.254")
	cloudMetadataIPv6 = net.ParseIP("fd00:ec2::254")
)

func init() {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",          // Current network ("this" network)
		"10.0.0.0/8",         // Private-use (RFC 1918)
		"100.64.0.0/10",      // Shared address space (CGNAT, RFC 6598)
		"127.0.0.0/8",        // Loopback (RFC 1122)
		"169.254.0.0/16",     // Link-local (RFC 3927)
		"172.16.0.0/12",      // Private-use (RFC 1918)
		"192.0.0.0/24",       // IETF Protocol Assignments (RFC 6890)
		"192.0.2.0/24",       // Documentation TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",     // 6to4 Relay Anycast (RFC 7526)
		"192.168.0.0/16",     // Private-use (RFC 1918)
		"198.18.0.0/15",      // Benchmarking (RFC 2544)
		"198.51.100.0/24",    // Documentation TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",     // Documentation TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",        // Multicast (RFC 5771)
		"240.0.0.0/4",        // Reserved (RFC 1112)
		"255.255.255.255/32", // Limited Broadcast (RFC 8190)

		// IPv6
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"64:ff9b::/96",  // IPv4-IPv6 translation
		"100::/64",      // Discard-only
		"2001::/23",     // IETF protocol assignments
		"2001:db8::/32", // Documentation
		"fc00::/7",      // Unique Local Address (ULA, RFC 4193)
		"fe80::/10",     // Link-Local Unicast (RFC 4291)
		"ff00::/8",      // Multicast (RFC 4291)
	}
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err == nil {
			nonGlobalCIDRs = append(nonGlobalCIDRs, block)
		}
	}
}

// ValidateCanaryDestination evaluates whether a canary URL is safe, authorized, and compliant
// with OAST network policies. Prohibits private networks, loopback addresses, cloud metadata,
// and unauthorized hosts unless explicitly permitted by Config.
func ValidateCanaryDestination(rawURL string, cfg Config) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("%w: empty URL", ErrUnauthorizedCanary)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrUnauthorizedCanary, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q unsupported; only http and https permitted", ErrUnauthorizedCanary, u.Scheme)
	}

	if u.User != nil {
		return fmt.Errorf("%w: embedded credentials prohibited in canary URL", ErrUnauthorizedCanary)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: missing hostname in canary URL", ErrUnauthorizedCanary)
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	// Hostname format validation: reject spaces, backslashes, control characters, leading/trailing dots
	if strings.ContainsAny(host, " \t\r\n/\\@?#:") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("%w: malformed hostname %q", ErrUnauthorizedCanary, host)
	}

	// Authorized hosts enforcement (if configured)
	if len(cfg.AuthorizedHosts) > 0 {
		matched := false
		for _, authHost := range cfg.AuthorizedHosts {
			cleanPattern := strings.ToLower(strings.TrimSpace(authHost))
			if cleanPattern == "" {
				continue
			}
			baseDomain := strings.TrimPrefix(strings.TrimPrefix(cleanPattern, "*"), ".")
			if baseDomain == "" {
				continue
			}
			if strings.HasPrefix(cleanPattern, "*.") || strings.HasPrefix(cleanPattern, ".") {
				// Exact domain match OR strict subdomain with dot separator
				if host == baseDomain || strings.HasSuffix(host, "."+baseDomain) {
					matched = true
					break
				}
			} else if host == cleanPattern {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: host %q is not in authorized canary hosts whitelist", ErrUnauthorizedCanary, host)
		}
	}

	// Always block cloud metadata endpoints unless explicitly authorized
	if isCloudMetadataHost(host) {
		return fmt.Errorf("%w: cloud metadata destination %q is strictly prohibited", ErrUnauthorizedCanary, host)
	}

	// Dword/integer IPv4 check (e.g. 2130706433 or 0x7f000001)
	if val, err := strconv.ParseUint(host, 0, 64); err == nil && val <= 0xFFFFFFFF {
		ip := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		return checkIPPolicy(ip, host, cfg)
	}

	// Dotted numeric IPv4 check
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		var octets [4]byte
		parsedAll := true
		for i, part := range parts {
			val, err := strconv.ParseUint(part, 0, 8)
			if err != nil {
				parsedAll = false
				break
			}
			octets[i] = byte(val)
		}
		if parsedAll {
			ip := net.IPv4(octets[0], octets[1], octets[2], octets[3])
			return checkIPPolicy(ip, host, cfg)
		}
	}

	// Direct IP check (IPv4 or IPv6)
	if ip := net.ParseIP(host); ip != nil {
		return checkIPPolicy(ip, host, cfg)
	}

	// Hostname safety checks
	if isLoopbackHostname(host) {
		if !cfg.AllowLoopback {
			return fmt.Errorf("%w: loopback host %q prohibited", ErrUnauthorizedCanary, host)
		}
		return nil
	}

	if isInternalHostname(host) {
		if !cfg.AllowPrivateIPs {
			return fmt.Errorf("%w: internal host %q prohibited", ErrUnauthorizedCanary, host)
		}
		return nil
	}

	// DNS resolution check (if host is not an IP literal and not explicitly loopback/internal)
	resolver := cfg.DNSResolver
	if resolver != nil {
		ips, err := resolver(context.Background(), host)
		if err != nil {
			return fmt.Errorf("%w: failed to resolve host %q: %v", ErrUnauthorizedCanary, host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("%w: host %q resolved to zero addresses", ErrUnauthorizedCanary, host)
		}
		for _, ip := range ips {
			if err := checkIPPolicy(ip, host, cfg); err != nil {
				return err
			}
		}
	} else {
		// Default DNS resolution with bounded timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if err := checkIPPolicy(ip, host, cfg); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func checkIPPolicy(ip net.IP, host string, cfg Config) error {
	if ip == nil {
		return fmt.Errorf("%w: invalid IP address", ErrUnauthorizedCanary)
	}

	// Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Cloud metadata addresses are strictly prohibited under all configurations
	if ip.Equal(cloudMetadataIPv4) || ip.Equal(cloudMetadataIPv6) {
		return fmt.Errorf("%w: cloud metadata destination %q is strictly prohibited", ErrUnauthorizedCanary, host)
	}

	// Loopback
	if ip.IsLoopback() {
		if !cfg.AllowLoopback {
			return fmt.Errorf("%w: loopback address %q prohibited", ErrUnauthorizedCanary, host)
		}
		return nil
	}

	// Private addresses
	if ip.IsPrivate() || isRFC1918OrULA(ip) {
		if !cfg.AllowPrivateIPs {
			return fmt.Errorf("%w: private network address %q prohibited", ErrUnauthorizedCanary, host)
		}
		return nil
	}

	// Link-local, multicast, unspecified, non-global
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || isNonGlobal(ip) {
		return fmt.Errorf("%w: non-global or reserved address %q prohibited", ErrUnauthorizedCanary, host)
	}

	return nil
}

func isCloudMetadataHost(host string) bool {
	return host == "169.254.169.254" ||
		host == "fd00:ec2::254" ||
		host == "metadata.google.internal" ||
		host == "instance-data" ||
		host == "metadata"
}

func isLoopbackHostname(host string) bool {
	return host == "localhost" ||
		strings.HasSuffix(host, ".localhost")
}

func isInternalHostname(host string) bool {
	if !strings.Contains(host, ".") {
		return true
	}
	return strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".lan") ||
		strings.HasSuffix(host, ".corp") ||
		strings.HasSuffix(host, ".home") ||
		strings.HasSuffix(host, ".intranet")
}

func isRFC1918OrULA(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// IPv6 ULA fc00::/7
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}

func isNonGlobal(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range nonGlobalCIDRs {
			if block.IP.To4() != nil && block.Contains(ip4) {
				return true
			}
		}
		return false
	}
	for _, block := range nonGlobalCIDRs {
		if block.IP.To4() == nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

// SanitizeInteractionData strips null bytes and dangerous control characters from raw callback input,
// and ensures any sensitive credentials or tokens in the callback payload are redacted.
func SanitizeInteractionData(data string) string {
	if data == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(data))
	for _, r := range data {
		if r == 0 {
			continue
		}
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return secrets.RedactText(b.String())
}

// SanitizeInteractionHeaders returns a copy of HTTP headers with sanitized and redacted values.
func SanitizeInteractionHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	clean := make(map[string]string, len(headers))
	for k, v := range headers {
		cleanK := strings.ToLower(strings.TrimSpace(k))
		clean[cleanK] = SanitizeInteractionData(v)
	}
	return clean
}
