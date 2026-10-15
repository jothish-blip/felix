package crawler

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

var (
	// zeroNet: 0.0.0.0/8 (RFC 1122 - "This host on this network")
	_, zeroNet, _ = net.ParseCIDR("0.0.0.0/8")
	// cgnatNet: 100.64.0.0/10 (RFC 6598 - Carrier-Grade NAT)
	_, cgnatNet, _ = net.ParseCIDR("100.64.0.0/10")
	// ulaNet: fc00::/7 (RFC 4193 - IPv6 Unique Local Address)
	_, ulaNet, _ = net.ParseCIDR("fc00::/7")
	// cloudMetadataIPv4: 169.254.169.254/32 (AWS/GCP/Azure/OpenStack metadata)
	cloudMetadataIPv4 = net.ParseIP("169.254.169.254")
	// cloudMetadataIPv6: fd00:ec2::254 (AWS IMDSv2 IPv6 metadata endpoint)
	cloudMetadataIPv6 = net.ParseIP("fd00:ec2::254")
)

// SSRFError represents a connection blocked by the SSRF security policy.
type SSRFError struct {
	Target string
	Host   string
	IP     net.IP
	Reason string
}

func (e *SSRFError) Error() string {
	if e.IP != nil {
		if e.Host != "" && e.Host != e.IP.String() {
			return fmt.Sprintf("SSRF security refusal: destination host %q resolved to prohibited IP %s (%s)", e.Host, e.IP.String(), e.Reason)
		}
		return fmt.Sprintf("SSRF security refusal: destination IP %s is prohibited (%s)", e.IP.String(), e.Reason)
	}
	if e.Host != "" {
		return fmt.Sprintf("SSRF security refusal for %s: %s", e.Host, e.Reason)
	}
	return fmt.Sprintf("SSRF security refusal: %s", e.Reason)
}

// Resolver defines the interface for resolving hostnames to IP addresses.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ProhibitedIPReason checks if an IP is prohibited under SSRF policy.
// Returns (true, reason) if prohibited, or (false, "") if allowed.
func ProhibitedIPReason(ip net.IP, allowLoopback, allowPrivate bool) (bool, string) {
	if ip == nil {
		return true, "nil or unparseable IP address"
	}

	// Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// 1. Cloud Metadata explicit check (169.254.169.254 and fd00:ec2::254 are never allowed)
	if ip.Equal(cloudMetadataIPv4) || ip.Equal(cloudMetadataIPv6) {
		return true, fmt.Sprintf("cloud metadata service address (%s)", ip.String())
	}

	// 2. Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		if !allowLoopback {
			return true, "loopback address"
		}
	}

	// 3. Link-local unicast & multicast (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local address"
	}

	// 4. Unspecified addresses (0.0.0.0, ::, 0.0.0.0/8)
	if ip.IsUnspecified() || zeroNet.Contains(ip) {
		return true, "unspecified or non-routable address"
	}

	// 5. Broadcast (255.255.255.255)
	if ip.Equal(net.IPv4bcast) {
		return true, "limited broadcast address"
	}

	// 6. Multicast (224.0.0.0/4, ff00::/8)
	if ip.IsMulticast() {
		return true, "multicast address"
	}

	// 7. Carrier-Grade NAT (100.64.0.0/10)
	if cgnatNet.Contains(ip) {
		return true, "Carrier-Grade NAT address (RFC 6598)"
	}

	// 8. IPv6 ULA (fc00::/7)
	if ulaNet.Contains(ip) {
		if !allowPrivate {
			return true, "IPv6 Unique Local Address (ULA fc00::/7)"
		}
	}

	// 9. RFC 1918 Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	if ip.IsPrivate() {
		if !allowPrivate {
			return true, "RFC 1918 private address"
		}
	}

	return false, ""
}

// IsProhibitedIP returns true if the IP is prohibited under SSRF policy.
func IsProhibitedIP(ip net.IP, allowLoopback, allowPrivate bool) bool {
	prohibited, _ := ProhibitedIPReason(ip, allowLoopback, allowPrivate)
	return prohibited
}

// SafeDialerOptions configures safe dialing with SSRF prevention.
type SafeDialerOptions struct {
	Timeout         time.Duration
	KeepAlive       time.Duration
	AllowLoopback   bool
	AllowPrivateIPs bool
	Resolver        Resolver
	DialFunc        func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSafeDialContext returns a DialContext function that performs pre-dial IP resolution,
// validates all resolved addresses against prohibited IP policies (preventing DNS rebinding),
// and directly dials the validated IP address while preserving Host and TLS SNI semantics.
func NewSafeDialContext(opts SafeDialerOptions) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.KeepAlive <= 0 {
		opts.KeepAlive = 30 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: opts.KeepAlive,
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid destination address %q: %w", addr, err)
		}

		// Check if host is an IP literal
		parsedIP := net.ParseIP(host)
		if parsedIP != nil {
			if prohibited, reason := ProhibitedIPReason(parsedIP, opts.AllowLoopback, opts.AllowPrivateIPs); prohibited {
				return nil, &SSRFError{Host: host, IP: parsedIP, Reason: reason}
			}
			// Safe IP literal: dial directly
			validatedAddr := net.JoinHostPort(parsedIP.String(), port)
			if opts.DialFunc != nil {
				return opts.DialFunc(ctx, network, validatedAddr)
			}
			return dialer.DialContext(ctx, network, validatedAddr)
		}

		// Hostname resolution
		ipAddrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ipAddrs) == 0 {
			return nil, fmt.Errorf("no IP addresses found for host %s", host)
		}

		// Validate ALL resolved addresses. If ANY resolved address is prohibited,
		// reject immediately to prevent dual-homed DNS rebinding tricks.
		for _, ipAddr := range ipAddrs {
			if prohibited, reason := ProhibitedIPReason(ipAddr.IP, opts.AllowLoopback, opts.AllowPrivateIPs); prohibited {
				return nil, &SSRFError{Host: host, IP: ipAddr.IP, Reason: reason}
			}
		}

		// Dial the validated addresses in sequence until one succeeds
		var lastErr error
		for _, ipAddr := range ipAddrs {
			validatedAddr := net.JoinHostPort(ipAddr.IP.String(), port)
			var conn net.Conn
			if opts.DialFunc != nil {
				conn, err = opts.DialFunc(ctx, network, validatedAddr)
			} else {
				conn, err = dialer.DialContext(ctx, network, validatedAddr)
			}
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// SafeTransportOptions configures an http.Transport equipped with SSRF safe dialing.
type SafeTransportOptions struct {
	Timeout               time.Duration
	KeepAlive             time.Duration
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	AllowLoopback         bool
	AllowPrivateIPs       bool
	InsecureSkipVerify    bool
	TLSConfig             *tls.Config
	Resolver              Resolver
	DialFunc              func(ctx context.Context, network, addr string) (net.Conn, error)
	Proxy                 func(*http.Request) (*url.URL, error)
}

// NewSafeTransport creates an http.Transport configured with safe dialing and SSRF protection.
func NewSafeTransport(opts SafeTransportOptions) *http.Transport {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.KeepAlive <= 0 {
		opts.KeepAlive = 30 * time.Second
	}
	if opts.IdleConnTimeout <= 0 {
		opts.IdleConnTimeout = 90 * time.Second
	}
	if opts.TLSHandshakeTimeout <= 0 {
		opts.TLSHandshakeTimeout = 10 * time.Second
	}
	if opts.ExpectContinueTimeout <= 0 {
		opts.ExpectContinueTimeout = 1 * time.Second
	}
	if opts.MaxIdleConns <= 0 {
		opts.MaxIdleConns = 100
	}
	if opts.MaxIdleConnsPerHost <= 0 {
		opts.MaxIdleConnsPerHost = 20
	}

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	if opts.InsecureSkipVerify {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.InsecureSkipVerify = true
	}

	dialContext := NewSafeDialContext(SafeDialerOptions{
		Timeout:         opts.Timeout,
		KeepAlive:       opts.KeepAlive,
		AllowLoopback:   opts.AllowLoopback,
		AllowPrivateIPs: opts.AllowPrivateIPs,
		Resolver:        opts.Resolver,
		DialFunc:        opts.DialFunc,
	})

	return &http.Transport{
		Proxy:                 opts.Proxy,
		DialContext:           dialContext,
		MaxIdleConns:          opts.MaxIdleConns,
		MaxIdleConnsPerHost:   opts.MaxIdleConnsPerHost,
		IdleConnTimeout:       opts.IdleConnTimeout,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ExpectContinueTimeout: opts.ExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsCfg,
	}
}
