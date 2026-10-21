package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"felix/pkg/secrets"
)

var (
	ErrInsecureHTTPNotAllowed = errors.New("insecure HTTP endpoint is prohibited; HTTPS is required")
	ErrInvalidWebhookURL      = errors.New("invalid webhook URL")
	ErrSSRFDestinationBlocked = errors.New("webhook destination blocked by SSRF protection: target resolves to private, loopback, or reserved network")
	ErrSSRFMetadataBlocked    = errors.New("webhook destination blocked: target resolves to link-local or cloud metadata service (169.254.169.254)")
	ErrTooManyRedirects       = errors.New("webhook request exceeded maximum redirect limit")
	ErrRedirectToUnsafeTarget = errors.New("webhook redirected to prohibited or unsafe destination")
)

// SSRFConfig holds safety policies for validating and resolving webhook destinations.
type SSRFConfig struct {
	AllowInsecureHTTP bool
	AllowPrivateIPs   bool
	AllowLoopback     bool
	MaxRedirects      int
	ResolveTimeout    time.Duration
}

// DefaultSSRFConfig returns standard, defensive SSRF configuration.
func DefaultSSRFConfig() SSRFConfig {
	return SSRFConfig{
		AllowInsecureHTTP: false,
		AllowPrivateIPs:   false,
		AllowLoopback:     false,
		MaxRedirects:      3,
		ResolveTimeout:    5 * time.Second,
	}
}

// ValidateEndpoint validates a destination URL against SSRF and scheme restrictions.
func ValidateEndpoint(rawURL string, cfg SSRFConfig) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: URL cannot be empty", ErrInvalidWebhookURL)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidWebhookURL, secrets.RedactText(err.Error()))
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" {
		if scheme == "http" {
			if !cfg.AllowInsecureHTTP {
				return nil, ErrInsecureHTTPNotAllowed
			}
		} else {
			return nil, fmt.Errorf("%w: unsupported scheme %q (must be https)", ErrInvalidWebhookURL, scheme)
		}
	}

	hostname := parsed.Hostname()
	if strings.TrimSpace(hostname) == "" {
		return nil, fmt.Errorf("%w: hostname cannot be empty", ErrInvalidWebhookURL)
	}

	// Always validate destination against prohibited IP ranges (including cloud metadata)
	if err := CheckSafeDestinationWithConfig(hostname, cfg.ResolveTimeout, cfg); err != nil {
		return nil, err
	}

	return parsed, nil
}

// CheckSafeDestination resolves a host and checks whether all resolved IPs are permitted.
func CheckSafeDestination(host string, timeout time.Duration) error {
	return CheckSafeDestinationWithConfig(host, timeout, DefaultSSRFConfig())
}

// CheckSafeDestinationWithConfig resolves host and verifies each resolved IP against policies.
func CheckSafeDestinationWithConfig(host string, timeout time.Duration, cfg SSRFConfig) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check if host is direct IP literal
	if ip := net.ParseIP(host); ip != nil {
		return ValidateIP(ip, cfg.AllowPrivateIPs, cfg.AllowLoopback)
	}

	// Resolve hostname
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("failed to resolve webhook host %s: %w", secrets.RedactText(host), err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses resolved for host %s", secrets.RedactText(host))
	}

	for _, ip := range ips {
		if err := ValidateIP(ip, cfg.AllowPrivateIPs, cfg.AllowLoopback); err != nil {
			return fmt.Errorf("%w: host %s resolves to restricted IP %s", err, secrets.RedactText(host), ip.String())
		}
	}

	return nil
}

// ValidateIP checks if an IP is permitted according to safety policies.
// Cloud metadata (169.254.169.254, fe80::/10), unspecified (0.0.0.0), and broadcast are ALWAYS prohibited,
// regardless of AllowPrivateIPs.
// Loopback (127.0.0.0/8, ::1) is prohibited unless AllowLoopback is true.
// Private networks (RFC 1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, RFC 4193 fc00::/7, 100.64.0.0/10)
// are prohibited unless AllowPrivateIPs is true.
func ValidateIP(ip net.IP, allowPrivateIPs bool, allowLoopback bool) error {
	if ip == nil {
		return fmt.Errorf("%w: invalid nil IP", ErrSSRFDestinationBlocked)
	}

	// 1. Unspecified (0.0.0.0, ::) - always blocked
	if ip.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address %s prohibited", ErrSSRFDestinationBlocked, ip.String())
	}

	// 2. Link-local and Cloud Metadata - ALWAYS BLOCKED even if allowPrivateIPs is true!
	// Link-local unicast (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: link-local/cloud metadata IP %s prohibited", ErrSSRFMetadataBlocked, ip.String())
	}
	// Multicast (224.0.0.0/4, ff00::/8)
	if ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: multicast IP %s prohibited", ErrSSRFDestinationBlocked, ip.String())
	}

	// 3. IPv4 representation checks (covers both standard IPv4 and IPv4-mapped IPv6)
	if v4 := ip.To4(); v4 != nil {
		// Explicit cloud metadata address: 169.254.169.254 or any 169.254.0.0/16
		if v4[0] == 169 && v4[1] == 254 {
			return fmt.Errorf("%w: cloud metadata address 169.254.x.x prohibited", ErrSSRFMetadataBlocked)
		}

		// 0.0.0.0/8
		if v4[0] == 0 {
			return fmt.Errorf("%w: 0.0.0.0/8 address prohibited", ErrSSRFDestinationBlocked)
		}

		// Loopback (127.0.0.0/8)
		if v4[0] == 127 {
			if !allowLoopback {
				return fmt.Errorf("%w: loopback IP %s prohibited", ErrSSRFDestinationBlocked, ip.String())
			}
			return nil
		}

		// RFC 1918 Private ranges
		isPrivateRFC := false
		if v4[0] == 10 {
			isPrivateRFC = true
		} else if v4[0] == 172 && (v4[1] >= 16 && v4[1] <= 31) {
			isPrivateRFC = true
		} else if v4[0] == 192 && v4[1] == 168 {
			isPrivateRFC = true
		} else if v4[0] == 100 && (v4[1]&192) == 64 { // Carrier-grade NAT (100.64.0.0/10)
			isPrivateRFC = true
		}

		if isPrivateRFC {
			if !allowPrivateIPs {
				return fmt.Errorf("%w: private network IP %s prohibited without explicit opt-in", ErrSSRFDestinationBlocked, ip.String())
			}
			return nil
		}

		// Broadcast (255.255.255.255)
		if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
			return fmt.Errorf("%w: broadcast IP prohibited", ErrSSRFDestinationBlocked)
		}

		return nil
	}

	// 4. IPv6-specific checks
	// Loopback (::1)
	if ip.IsLoopback() {
		if !allowLoopback {
			return fmt.Errorf("%w: loopback IPv6 %s prohibited", ErrSSRFDestinationBlocked, ip.String())
		}
		return nil
	}

	// Private IPv6 (RFC 4193 Unique Local fc00::/7)
	if ip.IsPrivate() {
		if !allowPrivateIPs {
			return fmt.Errorf("%w: private IPv6 %s prohibited without explicit opt-in", ErrSSRFDestinationBlocked, ip.String())
		}
		return nil
	}

	return nil
}
