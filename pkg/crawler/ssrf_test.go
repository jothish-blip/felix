package crawler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockResolver implements Resolver for deterministic offline DNS resolution tests.
type mockResolver struct {
	hosts map[string][]net.IPAddr
}

func newMockResolver(entries map[string][]string) *mockResolver {
	hosts := make(map[string][]net.IPAddr)
	for h, ipStrs := range entries {
		var addrs []net.IPAddr
		for _, ipStr := range ipStrs {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				addrs = append(addrs, net.IPAddr{IP: ip})
			}
		}
		hosts[strings.ToLower(h)] = addrs
	}
	return &mockResolver{hosts: hosts}
}

func (m *mockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m.hosts[strings.ToLower(host)]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{
		Err:        "no such host",
		Name:       host,
		IsNotFound: true,
	}
}

// 1. Loopback IPv4 blocked
func TestSSRF_1_LoopbackIPv4Blocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>loopback response</body></html>")
	}))
	defer ts.Close()

	// DefaultConfig has AllowLoopback = false (production default)
	c := New(DefaultConfig())
	res := c.Crawl(context.Background(), ts.URL)

	if res.Err == nil {
		t.Fatalf("expected crawl against loopback server %s to fail with SSRF refusal, but succeeded", ts.URL)
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked, got: %+v", res.Diagnostic)
	}
	if !strings.Contains(res.Err.Error(), "SSRF security refusal") || !strings.Contains(res.Err.Error(), "loopback address") {
		t.Errorf("expected SSRF loopback error message, got: %v", res.Err)
	}

	// Also test alternative loopback 127.0.0.2
	res2 := c.Crawl(context.Background(), "http://127.0.0.2:8080/test")
	if res2.Err == nil || res2.Diagnostic == nil || res2.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected 127.0.0.2 to be blocked by SSRF policy, got: %v", res2.Err)
	}
}

// 2. Loopback IPv6 blocked
func TestSSRF_2_LoopbackIPv6Blocked(t *testing.T) {
	c := New(DefaultConfig())
	res := c.Crawl(context.Background(), "http://[::1]:8080/secret")

	if res.Err == nil {
		t.Fatalf("expected connection to [::1] to fail, but got nil error")
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked, got: %+v", res.Diagnostic)
	}
	if !strings.Contains(res.Err.Error(), "loopback address") {
		t.Errorf("expected loopback error description, got: %v", res.Err)
	}
}

// 3. RFC 1918 private IPv4 ranges blocked
func TestSSRF_3_PrivateRFC1918Blocked(t *testing.T) {
	c := New(DefaultConfig())

	testCases := []struct {
		name string
		url  string
	}{
		{"10.0.0.0/8", "http://10.0.0.1:8080/admin"},
		{"172.16.0.0/12", "http://172.16.5.10:80/status"},
		{"192.168.0.0/16", "http://192.168.1.1:443/config"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := c.Crawl(context.Background(), tc.url)
			if res.Err == nil {
				t.Fatalf("expected %s to be blocked, got nil error", tc.url)
			}
			if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
				t.Errorf("expected ReachabilitySSRFBlocked for %s, got: %+v", tc.url, res.Diagnostic)
			}
			if !strings.Contains(res.Err.Error(), "RFC 1918 private address") {
				t.Errorf("expected RFC 1918 reason in error, got: %v", res.Err)
			}
		})
	}
}

// 4. IPv4 and IPv6 link-local addresses blocked
func TestSSRF_4_LinkLocalBlocked(t *testing.T) {
	c := New(DefaultConfig())

	testCases := []struct {
		name string
		url  string
	}{
		{"IPv4 Link-Local", "http://169.254.10.20:80/config"},
		{"IPv6 Link-Local", "http://[fe80::1ff:fe23:4567]:8080/info"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := c.Crawl(context.Background(), tc.url)
			if res.Err == nil {
				t.Fatalf("expected link-local address %s to be blocked", tc.url)
			}
			if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
				t.Errorf("expected ReachabilitySSRFBlocked, got: %+v", res.Diagnostic)
			}
			if !strings.Contains(res.Err.Error(), "link-local address") {
				t.Errorf("expected link-local reason, got: %v", res.Err)
			}
		})
	}
}

// 5. Unspecified and other prohibited addresses blocked
func TestSSRF_5_UnspecifiedAndProhibitedBlocked(t *testing.T) {
	c := New(DefaultConfig())

	testCases := []struct {
		name           string
		url            string
		expectedReason string
	}{
		{"Unspecified IPv4 0.0.0.0", "http://0.0.0.0:80/", "unspecified"},
		{"Unspecified IPv6 [::]", "http://[::]:8080/", "unspecified"},
		{"Carrier-Grade NAT 100.64.0.1", "http://100.64.0.1:8080/gw", "Carrier-Grade NAT"},
		{"IPv6 ULA [fc00::1]", "http://[fc00::1]:8080/private", "ULA"},
		{"Broadcast 255.255.255.255", "http://255.255.255.255:80/", "limited broadcast"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := c.Crawl(context.Background(), tc.url)
			if res.Err == nil {
				t.Fatalf("expected %s to be blocked, got nil error", tc.url)
			}
			if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
				t.Errorf("expected ReachabilitySSRFBlocked for %s, got: %+v", tc.url, res.Diagnostic)
			}
			if !strings.Contains(strings.ToLower(res.Err.Error()), strings.ToLower(tc.expectedReason)) {
				t.Errorf("expected error reason containing %q, got: %v", tc.expectedReason, res.Err)
			}
		})
	}
}

// 6. Cloud metadata IP destinations blocked (IPv4 169.254.169.254 and IPv6 fd00:ec2::254)
func TestSSRF_6_CloudMetadataBlocked(t *testing.T) {
	c := New(DefaultConfig())

	// Direct attempt to connect to AWS/GCP/Azure/OpenStack IPv4 metadata service
	metadataURL := "http://169.254.169.254/latest/meta-data/"
	res := c.Crawl(context.Background(), metadataURL)

	if res.Err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: metadata IPv4 %s was not blocked!", metadataURL)
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked, got: %+v", res.Diagnostic)
	}
	if !strings.Contains(res.Err.Error(), "cloud metadata service address") {
		t.Errorf("expected cloud metadata reason in error, got: %v", res.Err)
	}

	// Direct attempt to connect to AWS Nitro IMDSv2 IPv6 metadata endpoint fd00:ec2::254
	metadataIPv6URL := "http://[fd00:ec2::254]/latest/meta-data/"
	resIPv6 := c.Crawl(context.Background(), metadataIPv6URL)

	if resIPv6.Err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: metadata IPv6 %s was not blocked!", metadataIPv6URL)
	}
	if resIPv6.Diagnostic == nil || resIPv6.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked for IPv6 metadata, got: %+v", resIPv6.Diagnostic)
	}
	if !strings.Contains(resIPv6.Err.Error(), "cloud metadata service address (fd00:ec2::254)") {
		t.Errorf("expected IPv6 cloud metadata reason in error, got: %v", resIPv6.Err)
	}

	// Critical Policy Invariant: Metadata endpoints must be rejected UNCONDITIONALLY,
	// even when AllowPrivateIPs and AllowLoopback are both enabled.
	cfgPrivate := DefaultConfig()
	cfgPrivate.AllowPrivateIPs = true
	cfgPrivate.AllowLoopback = true
	cPrivate := New(cfgPrivate)

	resPrivateV4 := cPrivate.Crawl(context.Background(), metadataURL)
	if resPrivateV4.Err == nil || resPrivateV4.Diagnostic == nil || resPrivateV4.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Fatalf("CRITICAL SECURITY FAILURE: IPv4 cloud metadata was allowed when AllowPrivateIPs=true! err: %v", resPrivateV4.Err)
	}

	resPrivateV6 := cPrivate.Crawl(context.Background(), metadataIPv6URL)
	if resPrivateV6.Err == nil || resPrivateV6.Diagnostic == nil || resPrivateV6.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Fatalf("CRITICAL SECURITY FAILURE: IPv6 cloud metadata fd00:ec2::254 was allowed when AllowPrivateIPs=true! err: %v", resPrivateV6.Err)
	}

	// Verify authorized private-network addresses ARE allowed when AllowPrivateIPs is enabled
	if prohibited, reason := ProhibitedIPReason(net.ParseIP("10.0.0.1"), false, true); prohibited {
		t.Errorf("expected RFC 1918 10.0.0.1 to be allowed when AllowPrivateIPs=true, but blocked: %s", reason)
	}
	if prohibited, reason := ProhibitedIPReason(net.ParseIP("fc00::1"), false, true); prohibited {
		t.Errorf("expected ULA fc00::1 to be allowed when AllowPrivateIPs=true, but blocked: %s", reason)
	}
	if prohibited, reason := ProhibitedIPReason(net.ParseIP("fd12:3456:789a::1"), false, true); prohibited {
		t.Errorf("expected ULA fd12:3456:789a::1 to be allowed when AllowPrivateIPs=true, but blocked: %s", reason)
	}

	// Also verify redirect from an allowed target to cloud metadata is blocked immediately
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v6" {
			http.Redirect(w, r, "http://[fd00:ec2::254]/latest/meta-data/", http.StatusFound)
			return
		}
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	}))
	defer redirectServer.Close()

	cfg := testConfig() // allow loopback for initial server only
	c2 := New(cfg)
	resRedirect := c2.Crawl(context.Background(), redirectServer.URL)
	if resRedirect.Err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: redirect to cloud metadata was followed!")
	}
	if resRedirect.Diagnostic == nil || resRedirect.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked on metadata redirect, got: %+v", resRedirect.Diagnostic)
	}
	if !strings.Contains(resRedirect.Err.Error(), "cloud metadata service address") {
		t.Errorf("expected cloud metadata in error, got: %v", resRedirect.Err)
	}

	// Redirect to IPv6 cloud metadata
	resRedirectV6 := c2.Crawl(context.Background(), redirectServer.URL+"/v6")
	if resRedirectV6.Err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: redirect to IPv6 cloud metadata was followed!")
	}
	if resRedirectV6.Diagnostic == nil || resRedirectV6.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked on IPv6 metadata redirect, got: %+v", resRedirectV6.Diagnostic)
	}
}

// 7. IPv4-mapped IPv6 handling
func TestSSRF_7_IPv4MappedIPv6Handling(t *testing.T) {
	c := New(DefaultConfig())

	testCases := []struct {
		name           string
		url            string
		expectedReason string
	}{
		{"IPv4-mapped Loopback", "http://[::ffff:127.0.0.1]:8080/debug", "loopback"},
		{"IPv4-mapped Cloud Metadata", "http://[::ffff:169.254.169.254]:80/latest", "cloud metadata"},
		{"IPv4-mapped RFC 1918 Class A", "http://[::ffff:10.0.0.1]:8080/status", "RFC 1918"},
		{"IPv4-mapped RFC 1918 Class C", "http://[::ffff:192.168.1.1]:8080/router", "RFC 1918"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := c.Crawl(context.Background(), tc.url)
			if res.Err == nil {
				t.Fatalf("expected IPv4-mapped IPv6 address %s to be blocked", tc.url)
			}
			if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
				t.Errorf("expected ReachabilitySSRFBlocked, got: %+v", res.Diagnostic)
			}
			if !strings.Contains(strings.ToLower(res.Err.Error()), strings.ToLower(tc.expectedReason)) {
				t.Errorf("expected reason %q, got: %v", tc.expectedReason, res.Err)
			}
		})
	}
}

// 8. A hostname resolving to a prohibited address blocked before a TCP connection occurs
func TestSSRF_8_HostnameResolvingToProhibitedAddressBlocked(t *testing.T) {
	resolver := newMockResolver(map[string][]string{
		"internal.corp.local": {"10.20.30.40"},
		"localhost.local":     {"127.0.0.1"},
		"metadata.cloud":      {"169.254.169.254"},
		"metadata.ipv6.cloud": {"fd00:ec2::254"},
	})

	var tcpDialAttempts atomic.Int32
	mockDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpDialAttempts.Add(1)
		return nil, fmt.Errorf("unexpected TCP connection attempt to %s", addr)
	}

	cfg := Config{
		Timeout:  2 * time.Second,
		Resolver: resolver,
		DialFunc: mockDialer,
	}
	c := New(cfg)

	targets := []string{
		"http://internal.corp.local/api",
		"http://localhost.local/console",
		"http://metadata.cloud/v1",
		"http://metadata.ipv6.cloud/v1",
	}

	for _, target := range targets {
		res := c.Crawl(context.Background(), target)
		if res.Err == nil {
			t.Fatalf("expected crawl against %s to fail", target)
		}
		if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySSRFBlocked {
			t.Errorf("expected ReachabilitySSRFBlocked for %s, got: %+v", target, res.Diagnostic)
		}
	}

	// Crucial assertion: ZERO TCP connection attempts occurred!
	if dials := tcpDialAttempts.Load(); dials != 0 {
		t.Fatalf("SECURITY FAILURE: %d TCP dial attempts were made against prohibited destinations!", dials)
	}
}

// 9. DNS rebinding / resolution changing between validation and dialing cannot bypass protection
func TestSSRF_9_DNSRebindingBlocked(t *testing.T) {
	// Simulate dual-homed DNS entry returning both a public IP and an internal loopback IP
	resolver := newMockResolver(map[string][]string{
		"dual-homed.attacker.com": {"93.184.216.34", "127.0.0.1"},
		"rebind.attacker.com":     {"127.0.0.1"},
	})

	var tcpDials atomic.Int32
	mockDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpDials.Add(1)
		return nil, fmt.Errorf("unexpected TCP dial to %s", addr)
	}

	cfg := Config{
		Timeout:  2 * time.Second,
		Resolver: resolver,
		DialFunc: mockDialer,
	}
	c := New(cfg)

	// Dual-homed domain containing prohibited address must fail before dialing
	resDual := c.Crawl(context.Background(), "http://dual-homed.attacker.com/")
	if resDual.Err == nil {
		t.Fatalf("expected dual-homed DNS lookup to fail")
	}
	if resDual.Diagnostic == nil || resDual.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked for dual-homed DNS, got: %+v", resDual.Diagnostic)
	}

	// Rebinding domain
	resRebind := c.Crawl(context.Background(), "http://rebind.attacker.com/")
	if resRebind.Err == nil {
		t.Fatalf("expected rebind DNS lookup to fail")
	}
	if resRebind.Diagnostic == nil || resRebind.Diagnostic.Category != ReachabilitySSRFBlocked {
		t.Errorf("expected ReachabilitySSRFBlocked for rebind DNS, got: %+v", resRebind.Diagnostic)
	}

	if dials := tcpDials.Load(); dials != 0 {
		t.Fatalf("SECURITY FAILURE: %d TCP dials were made on rebinding / dual-homed targets!", dials)
	}
}

// 10. A redirect to an out-of-scope hostname is rejected
func TestSSRF_10_OutOfScopeRedirectRejected(t *testing.T) {
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://out-of-scope.example.org/leaked-session", http.StatusFound)
	}))
	defer primaryServer.Close()

	cfg := testConfig()
	cfg.ScopeMode = ScopeSameOrigin
	c := New(cfg)

	res := c.Crawl(context.Background(), primaryServer.URL)
	if res.Err == nil {
		t.Fatalf("expected out-of-scope redirect to be rejected, got nil error")
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilityRedirectError {
		t.Errorf("expected ReachabilityRedirectError, got: %+v", res.Diagnostic)
	}
	if !strings.Contains(res.Err.Error(), "cross-host redirect") && !strings.Contains(res.Err.Error(), "out of crawler scope") {
		t.Errorf("expected out-of-scope redirect error message, got: %v", res.Err)
	}
}

// 11. A multi-hop redirect cannot escape the original authorization scope
func TestSSRF_11_MultiHopRedirectEscapeRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hop1":
			http.Redirect(w, r, "/hop2", http.StatusFound)
		case "/hop2":
			// Attempt to escape origin on second hop
			http.Redirect(w, r, "https://thirdparty.attacker.com/steal", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.ScopeMode = ScopeSameOrigin
	c := New(cfg)

	res := c.Crawl(context.Background(), server.URL+"/hop1")
	if res.Err == nil {
		t.Fatalf("expected multi-hop redirect escape to fail, got nil error")
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilityRedirectError {
		t.Errorf("expected ReachabilityRedirectError, got: %+v", res.Diagnostic)
	}
}

// 12. A safe same-scope redirect still works
func TestSSRF_12_SafeSameScopeRedirectAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			http.Redirect(w, r, "/step2", http.StatusFound)
		case "/step2":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><script src="/asset.js"></script><h1>Success</h1></html>`)
		case "/asset.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("valid asset");`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.ScopeMode = ScopeSameOrigin
	c := New(cfg)

	res := c.Crawl(context.Background(), server.URL+"/step1")
	if res.Err != nil {
		t.Fatalf("expected safe same-scope redirect to succeed, got: %v", res.Err)
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySuccess {
		t.Errorf("expected ReachabilitySuccess, got: %+v", res.Diagnostic)
	}
	if len(res.Assets) != 1 {
		t.Errorf("expected 1 asset discovered after redirect, got %d", len(res.Assets))
	}
}

// 13. A permitted public test address is handled through a mock dialer without making an external network connection
func TestSSRF_13_PermittedPublicTestAddressWithMockDialer(t *testing.T) {
	// Public IP for example.com: 93.184.216.34
	publicHost := "example.com"
	publicIP := "93.184.216.34"
	publicTarget := "http://" + publicHost + "/index.html"

	resolver := newMockResolver(map[string][]string{
		publicHost: {publicIP},
	})

	var packetsSent atomic.Int32
	mockDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		packetsSent.Add(1)
		// Return in-memory pipe connection (zero network traffic)
		clientConn, serverConn := net.Pipe()

		go func() {
			defer serverConn.Close()
			req, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err != nil {
				return
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`<html><body>Static Public Page</body></html>`)),
				Request:    req,
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Write(serverConn)
		}()

		return clientConn, nil
	}

	cfg := Config{
		Timeout:  2 * time.Second,
		Resolver: resolver,
		DialFunc: mockDialer,
	}
	c := New(cfg)

	res := c.Crawl(context.Background(), publicTarget)
	if res.Err != nil {
		t.Fatalf("expected mock public crawl to succeed, got: %v", res.Err)
	}
	if res.Diagnostic == nil || res.Diagnostic.Category != ReachabilitySuccess {
		t.Errorf("expected ReachabilitySuccess, got: %+v", res.Diagnostic)
	}
	if packets := packetsSent.Load(); packets != 1 {
		t.Errorf("expected 1 handled mock connection, got %d", packets)
	}
}

// 14. Malformed redirect destinations fail safely
func TestSSRF_14_MalformedRedirectDestinationsFailSafely(t *testing.T) {
	testCases := []struct {
		name        string
		destination string
	}{
		{"File Scheme", "file:///etc/passwd"},
		{"Javascript Scheme", "javascript:alert(1)"},
		{"Gopher Scheme", "gopher://127.0.0.1:70/"},
		{"Credentials Embedded", "http://admin:secret@target.com/private"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.destination, http.StatusFound)
			}))
			defer server.Close()

			cfg := testConfig()
			c := New(cfg)

			res := c.Crawl(context.Background(), server.URL)
			if res.Err == nil {
				t.Fatalf("expected redirect to %s to fail safely", tc.destination)
			}
		})
	}
}

// 15. Redirect loops, timeouts, and request cancellation remain correctly handled
func TestSSRF_15_RedirectLoopsTimeoutsAndCancellation(t *testing.T) {
	// 1. Redirect Loop
	loopServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loopA" {
			http.Redirect(w, r, "/loopB", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/loopA", http.StatusFound)
	}))
	defer loopServer.Close()

	cfg := testConfig()
	c := New(cfg)

	resLoop := c.Crawl(context.Background(), loopServer.URL+"/loopA")
	if resLoop.Err == nil {
		t.Fatalf("expected redirect loop to fail, got nil error")
	}
	if resLoop.Diagnostic == nil || resLoop.Diagnostic.Category != ReachabilityRedirectError {
		t.Errorf("expected ReachabilityRedirectError on loop, got: %+v", resLoop.Diagnostic)
	}
	if !strings.Contains(resLoop.Err.Error(), "stopped after 10 redirects") {
		t.Errorf("expected 10 redirects limit, got: %v", resLoop.Err)
	}

	// 2. Timeout handling
	hangingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer hangingServer.Close()

	cfgTimeout := testConfig()
	cfgTimeout.Timeout = 50 * time.Millisecond
	cTimeout := New(cfgTimeout)

	resTimeout := cTimeout.Crawl(context.Background(), hangingServer.URL)
	if resTimeout.Err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if resTimeout.Diagnostic == nil || resTimeout.Diagnostic.Category != ReachabilityTimeout {
		t.Errorf("expected ReachabilityTimeout, got: %+v", resTimeout.Diagnostic)
	}

	// 3. Request cancellation via Context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	resCancel := c.Crawl(ctx, loopServer.URL)
	if resCancel.Err == nil {
		t.Fatalf("expected error on cancelled context, got nil")
	}
}
