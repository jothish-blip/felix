package browser

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Architectural Scope Note:
// CDP fetch-level request interception operates at the browser application layer.
// It intercepts and validates URLs before Chromium fulfills them. However, CDP request
// interception alone DOES NOT constitute a complete, self-sufficient SSRF defense against
// network-level attacks such as post-handshake DNS rebinding. Comprehensive SSRF prevention
// requires pairing CDP interception with Go's transport-level SafeDialer socket pinning
// and OS/cloud egress firewall controls.

var (
	_, zeroNetCIDR, _  = net.ParseCIDR("0.0.0.0/8")
	_, cgnatNetCIDR, _ = net.ParseCIDR("100.64.0.0/10")
	_, ulaNetCIDR, _   = net.ParseCIDR("fc00::/7")
	cloudMetadataV4    = net.ParseIP("169.254.169.254")
	cloudMetadataV6    = net.ParseIP("fd00:ec2::254")
)

// InterceptedRequest models a browser-initiated HTTP request captured by CDP.
type InterceptedRequest struct {
	RequestID    string
	URL          string
	Method       string
	Headers      map[string]string
	PostData     string
	HasPostData  bool
	ResourceType network.ResourceType
	Timestamp    time.Time
	Blocked      bool
	BlockReason  string
}

// InterceptedResponse models an HTTP response received over CDP.
type InterceptedResponse struct {
	RequestID  string
	URL        string
	Status     int64
	StatusText string
	Headers    map[string]string
	MimeType   string
	RemoteIP   string
	Timestamp  time.Time
}

// GatewayOptions configures the SafeDialer browser gateway and network sniffer.
type GatewayOptions struct {
	// AllowLoopback permits navigation/requests to 127.0.0.0/8 and localhost (e.g. for local test labs).
	AllowLoopback bool

	// AllowPrivateIPs permits RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
	AllowPrivateIPs bool

	// AllowedHosts defines explicit whitelist hosts (e.g. "127.0.0.1:8080") that bypass loopback checks.
	AllowedHosts []string

	// CustomPolicy allows injecting external URL verification rules.
	CustomPolicy func(targetURL string) (blocked bool, reason string)
}

// NetworkGateway orchestrates CDP network sniffing and SSRF request interception.
type NetworkGateway struct {
	opts      GatewayOptions
	inst      *Instance
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	requests  []*InterceptedRequest
	responses []*InterceptedResponse
	blocked   []*InterceptedRequest
	apiRoutes map[string]struct{}
	closed    bool
}

// IsProhibitedURL evaluates whether a target URL violates SSRF, loopback, or private IP policies.
func IsProhibitedURL(rawURL string, allowLoopback, allowPrivate bool) (bool, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true, "unparseable destination URL"
	}

	hostname := u.Hostname()
	if hostname == "" {
		return false, ""
	}

	lowerHost := strings.ToLower(hostname)

	// 1. Hostname-level checks
	if lowerHost == "metadata.google.internal" || lowerHost == "instance-data" {
		return true, "cloud metadata service hostname"
	}
	if lowerHost == "localhost" {
		if !allowLoopback {
			return true, "prohibited loopback hostname (localhost)"
		}
	}

	// 2. IP Parsing & DNS resolution
	parsedIP := net.ParseIP(hostname)

	// Check for numeric integer representation of IPv4 (e.g. 2130706433 for 127.0.0.1)
	if parsedIP == nil && isNumericString(hostname) {
		if intVal, err := strconv.ParseUint(hostname, 10, 32); err == nil {
			parsedIP = net.IPv4(byte(intVal>>24), byte(intVal>>16), byte(intVal>>8), byte(intVal))
		}
	}

	// Check for hexadecimal representation of IPv4 (e.g. 0x7f000001)
	if parsedIP == nil && strings.HasPrefix(strings.ToLower(hostname), "0x") {
		if hexVal, err := strconv.ParseUint(hostname[2:], 16, 32); err == nil {
			parsedIP = net.IPv4(byte(hexVal>>24), byte(hexVal>>16), byte(hexVal>>8), byte(hexVal))
		}
	}

	if parsedIP == nil {
		// Attempt local DNS resolution to catch DNS rebinding or internal domain names
		ips, err := net.LookupIP(hostname)
		if err == nil && len(ips) > 0 {
			parsedIP = ips[0]
		}
	}

	if parsedIP != nil {
		if v4 := parsedIP.To4(); v4 != nil {
			parsedIP = v4
		}

		// Cloud Metadata check (169.254.169.254 is NEVER allowed under any circumstances)
		if parsedIP.Equal(cloudMetadataV4) || parsedIP.Equal(cloudMetadataV6) {
			return true, fmt.Sprintf("prohibited cloud metadata IP address (%s)", parsedIP.String())
		}

		// Loopback checks (127.0.0.0/8, ::1)
		if parsedIP.IsLoopback() {
			if !allowLoopback {
				return true, fmt.Sprintf("prohibited loopback address (%s)", parsedIP.String())
			}
		}

		// Link-Local checks (169.254.0.0/16, fe80::/10)
		if parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
			return true, fmt.Sprintf("prohibited link-local address (%s)", parsedIP.String())
		}

		// Unspecified (0.0.0.0/8)
		if parsedIP.IsUnspecified() || zeroNetCIDR.Contains(parsedIP) {
			return true, fmt.Sprintf("prohibited non-routable address (%s)", parsedIP.String())
		}

		// Carrier-Grade NAT (100.64.0.0/10)
		if cgnatNetCIDR.Contains(parsedIP) {
			return true, fmt.Sprintf("prohibited Carrier-Grade NAT address (%s)", parsedIP.String())
		}

		// IPv6 ULA (fc00::/7)
		if ulaNetCIDR.Contains(parsedIP) {
			if !allowPrivate {
				return true, fmt.Sprintf("prohibited IPv6 ULA address (%s)", parsedIP.String())
			}
		}

		// RFC 1918 Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
		if parsedIP.IsPrivate() {
			if !allowPrivate {
				return true, fmt.Sprintf("prohibited RFC 1918 private address (%s)", parsedIP.String())
			}
		}
	}

	return false, ""
}

// AttachNetworkGateway enables CDP network sniffing and fetch-level SSRF request interception on an instance.
func AttachNetworkGateway(parentCtx context.Context, inst *Instance, opts GatewayOptions) (*NetworkGateway, error) {
	gatewayCtx, gatewayCancel := context.WithCancel(inst.Ctx)

	gw := &NetworkGateway{
		opts:      opts,
		inst:      inst,
		ctx:       gatewayCtx,
		cancel:    gatewayCancel,
		apiRoutes: make(map[string]struct{}),
	}

	// 1. Subscribe to Fetch.requestPaused events BEFORE enabling Fetch domain
	fetchEvents := chromedp.Events(gatewayCtx, fetch.RequestPaused)
	if _, err := chromedp.Call(inst.Ctx, fetch.Enable, fetch.EnableParams{}); err != nil {
		gatewayCancel()
		return nil, fmt.Errorf("failed enabling CDP Fetch domain: %w", err)
	}

	// 2. Subscribe to Network domain events
	reqEvents := chromedp.Events(gatewayCtx, network.RequestWillBeSent)
	respEvents := chromedp.Events(gatewayCtx, network.ResponseReceived)
	if _, err := chromedp.Call(inst.Ctx, network.Enable, network.EnableParams{}); err != nil {
		gatewayCancel()
		return nil, fmt.Errorf("failed enabling CDP Network domain: %w", err)
	}

	// 3. Launch Fetch Interception Event Loop
	go gw.runFetchInterceptionLoop(fetchEvents)

	// 4. Launch Network Sniffing Event Loops
	go gw.runRequestSnifferLoop(reqEvents)
	go gw.runResponseSnifferLoop(respEvents)

	return gw, nil
}

func (gw *NetworkGateway) runFetchInterceptionLoop(events iter.Seq2[fetch.EventRequestPaused, error]) {
	for ev, err := range events {
		if err != nil || gw.ctx.Err() != nil {
			return
		}

		go func(event fetch.EventRequestPaused) {
			reqURL := event.Request.URL
			blocked, reason := gw.evaluateURLPolicy(reqURL)

			if blocked {
				gw.mu.Lock()
				blockedReq := &InterceptedRequest{
					RequestID:    string(event.RequestID),
					URL:          reqURL,
					Method:       event.Request.Method,
					Headers:      convertHeaders(event.Request.Headers),
					PostData:     extractPostData(event.Request),
					HasPostData:  event.Request.HasPostData,
					ResourceType: event.ResourceType,
					Timestamp:    time.Now(),
					Blocked:      true,
					BlockReason:  reason,
				}
				gw.blocked = append(gw.blocked, blockedReq)
				gw.mu.Unlock()

				// Kill prohibited request at browser level
				_, _ = chromedp.Call(gw.inst.Ctx, fetch.FailRequest, fetch.FailRequestParams{
					RequestID:   event.RequestID,
					ErrorReason: network.ErrorReasonBlockedByClient,
				})
			} else {
				// Allow valid request to proceed
				_, _ = chromedp.Call(gw.inst.Ctx, fetch.ContinueRequest, fetch.ContinueRequestParams{
					RequestID: event.RequestID,
				})
			}
		}(ev)
	}
}

func (gw *NetworkGateway) runRequestSnifferLoop(events iter.Seq2[network.EventRequestWillBeSent, error]) {
	for ev, err := range events {
		if err != nil || gw.ctx.Err() != nil {
			return
		}

		req := &InterceptedRequest{
			RequestID:    string(ev.RequestID),
			URL:          ev.Request.URL,
			Method:       ev.Request.Method,
			Headers:      convertHeaders(ev.Request.Headers),
			PostData:     extractPostData(ev.Request),
			HasPostData:  ev.Request.HasPostData,
			ResourceType: ev.Type,
			Timestamp:    time.Now(),
		}

		gw.mu.Lock()
		gw.requests = append(gw.requests, req)

		// Catalog dynamic background XHR / Fetch API endpoints
		if ev.Type == network.ResourceTypeXHR || ev.Type == network.ResourceTypeFetch {
			gw.apiRoutes[ev.Request.URL] = struct{}{}
		}
		gw.mu.Unlock()
	}
}

func (gw *NetworkGateway) runResponseSnifferLoop(events iter.Seq2[network.EventResponseReceived, error]) {
	for ev, err := range events {
		if err != nil || gw.ctx.Err() != nil {
			return
		}

		resp := &InterceptedResponse{
			RequestID:  string(ev.RequestID),
			URL:        ev.Response.URL,
			Status:     ev.Response.Status,
			StatusText: ev.Response.StatusText,
			Headers:    convertHeaders(ev.Response.Headers),
			MimeType:   ev.Response.MimeType,
			RemoteIP:   ev.Response.RemoteIPAddress,
			Timestamp:  time.Now(),
		}

		gw.mu.Lock()
		gw.responses = append(gw.responses, resp)
		gw.mu.Unlock()
	}
}

func (gw *NetworkGateway) evaluateURLPolicy(rawURL string) (bool, string) {
	// Cloud metadata is strictly forbidden under all circumstances
	lowerURL := strings.ToLower(rawURL)
	if strings.Contains(lowerURL, "169.254.169.254") ||
		strings.Contains(lowerURL, "fd00:ec2::254") ||
		strings.Contains(lowerURL, "metadata.google.internal") ||
		strings.Contains(lowerURL, "instance-data") {
		return true, "prohibited cloud metadata endpoint"
	}

	// Whitelist check
	u, err := url.Parse(rawURL)
	if err == nil {
		for _, allowed := range gw.opts.AllowedHosts {
			if u.Host == allowed || strings.EqualFold(u.Hostname(), allowed) || strings.HasPrefix(rawURL, allowed) {
				return false, ""
			}
		}
	}

	if gw.opts.CustomPolicy != nil {
		if blocked, reason := gw.opts.CustomPolicy(rawURL); blocked {
			return true, reason
		}
	}

	return IsProhibitedURL(rawURL, gw.opts.AllowLoopback, gw.opts.AllowPrivateIPs)
}

// Stop shuts down the network sniffer and detaches event listeners.
func (gw *NetworkGateway) Stop() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.closed {
		return
	}
	gw.closed = true
	if gw.cancel != nil {
		gw.cancel()
	}
	if gw.inst != nil && gw.inst.Ctx != nil && gw.inst.Ctx.Err() == nil {
		_, _ = chromedp.Call(gw.inst.Ctx, fetch.Disable, cdp.Empty{})
		_, _ = chromedp.Call(gw.inst.Ctx, network.Disable, cdp.Empty{})
	}
}

// GetRequests returns a snapshot of all intercepted requests.
func (gw *NetworkGateway) GetRequests() []*InterceptedRequest {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	copied := make([]*InterceptedRequest, len(gw.requests))
	copy(copied, gw.requests)
	return copied
}

// GetResponses returns a snapshot of all captured HTTP responses.
func (gw *NetworkGateway) GetResponses() []*InterceptedResponse {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	copied := make([]*InterceptedResponse, len(gw.responses))
	copy(copied, gw.responses)
	return copied
}

// GetBlockedRequests returns all requests intercepted and killed by SafeDialer policy.
func (gw *NetworkGateway) GetBlockedRequests() []*InterceptedRequest {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	copied := make([]*InterceptedRequest, len(gw.blocked))
	copy(copied, gw.blocked)
	return copied
}

// GetAPIRoutes returns all unique dynamic API routes (XHR/Fetch) discovered during the session.
func (gw *NetworkGateway) GetAPIRoutes() []string {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	routes := make([]string, 0, len(gw.apiRoutes))
	for r := range gw.apiRoutes {
		routes = append(routes, r)
	}
	return routes
}

// FindRequestByURL searches intercepted requests for a matching URL substring.
func (gw *NetworkGateway) FindRequestByURL(sub string) *InterceptedRequest {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	for _, req := range gw.requests {
		if strings.Contains(req.URL, sub) {
			return req
		}
	}
	return nil
}

// FindBlockedByURL searches blocked requests for a matching URL substring.
func (gw *NetworkGateway) FindBlockedByURL(sub string) *InterceptedRequest {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	for _, req := range gw.blocked {
		if strings.Contains(req.URL, sub) {
			return req
		}
	}
	return nil
}

func extractPostData(req *network.Request) string {
	if req == nil || len(req.PostDataEntries) == 0 {
		return ""
	}
	var b strings.Builder
	for _, entry := range req.PostDataEntries {
		if entry != nil && len(entry.Bytes) > 0 {
			b.Write(entry.Bytes)
		}
	}
	return b.String()
}

func convertHeaders(h network.Headers) map[string]string {
	if h == nil {
		return nil
	}
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = fmt.Sprintf("%v", v)
	}
	return m
}

var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"apikey":              {},
	"secret":              {},
}

// RedactHeaders masks sensitive authentication tokens and session cookies for evidence retention.
func RedactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	redacted := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if _, isSensitive := sensitiveHeaders[lowerK]; isSensitive {
			redacted[k] = "[REDACTED_BY_SECURITY_POLICY]"
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

func isNumericString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
