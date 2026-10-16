package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"felix/pkg/crawler"
)

// Common probing errors
var (
	ErrRateLimited      = errors.New("rate limited by target (HTTP 429)")
	ErrResponseTooLarge = errors.New("cloud probe response exceeds size limit")
)

const (
	DefaultProbeTimeout     = 8 * time.Second
	DefaultMaxCloudResponse = 1024 * 1024 // 1 MB limit for safe probing
	DefaultUserAgent        = "Felix/0.1 (Defensive Security Auditing)"
)

// ClientOptions configures the safe probe client.
type ClientOptions struct {
	Timeout         time.Duration
	MaxResponseSize int64
	UserAgent       string
	HTTPClient      *http.Client
	AllowLoopback   bool
	AllowPrivateIPs bool
	DialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
	IsAllowed       func(string) bool
	IsExcluded      func(string) bool
}

// Client manages safe, bounded outbound HTTP requests and TCP probes for cloud service verification.
type Client struct {
	httpClient      *http.Client
	timeout         time.Duration
	maxResponseSize int64
	userAgent       string
	allowLoopback   bool
	allowPrivate    bool
	dialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
	isAllowed       func(string) bool
	isExcluded      func(string) bool
}

// NewClient initializes a hardened, bounded probe client.
func NewClient(opts ...ClientOptions) *Client {
	timeout := DefaultProbeTimeout
	maxSize := int64(DefaultMaxCloudResponse)
	ua := DefaultUserAgent
	var customHTTP *http.Client
	var allowLoopback bool
	var allowPrivate bool
	var isAllowed func(string) bool
	var isExcluded func(string) bool

	var customDial func(ctx context.Context, network, addr string) (net.Conn, error)

	if len(opts) > 0 {
		if opts[0].Timeout > 0 {
			timeout = opts[0].Timeout
		}
		if opts[0].MaxResponseSize > 0 {
			maxSize = opts[0].MaxResponseSize
		}
		if opts[0].UserAgent != "" {
			ua = opts[0].UserAgent
		}
		if opts[0].HTTPClient != nil {
			customHTTP = opts[0].HTTPClient
		}
		allowLoopback = opts[0].AllowLoopback
		allowPrivate = opts[0].AllowPrivateIPs
		customDial = opts[0].DialContext
		isAllowed = opts[0].IsAllowed
		isExcluded = opts[0].IsExcluded
	}

	if customDial == nil {
		customDial = crawler.NewSafeDialContext(crawler.SafeDialerOptions{
			Timeout:         timeout,
			AllowLoopback:   allowLoopback,
			AllowPrivateIPs: allowPrivate,
		})
	}

	if customHTTP == nil {
		transport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:         timeout,
			AllowLoopback:   allowLoopback,
			AllowPrivateIPs: allowPrivate,
		})

		customHTTP = &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				scheme := strings.ToLower(req.URL.Scheme)
				if scheme != "http" && scheme != "https" {
					return fmt.Errorf("redirect to unsupported scheme %q blocked", req.URL.Scheme)
				}
				if req.URL.User != nil {
					return fmt.Errorf("redirect with embedded credentials blocked")
				}
				destHost := req.URL.Hostname()
				if ip := net.ParseIP(destHost); ip != nil {
					if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLoopback, allowPrivate); prohibited {
						return &crawler.SSRFError{Host: destHost, IP: ip, Reason: reason}
					}
				}
				nextURL := req.URL.String()
				if isExcluded != nil && isExcluded(nextURL) {
					return fmt.Errorf("redirect to %s blocked: matches exclusion rule", nextURL)
				}
				if isAllowed != nil && !isAllowed(nextURL) {
					return fmt.Errorf("redirect to %s blocked: out of approved scope", nextURL)
				}
				// Prevent cross-origin redirect following to enforce cloud boundary
				if len(via) > 0 {
					origHost := via[0].URL.Host
					if req.URL.Host != origHost {
						return http.ErrUseLastResponse
					}
				}
				return nil
			},
		}
	}

	return &Client{
		httpClient:      customHTTP,
		timeout:         timeout,
		maxResponseSize: maxSize,
		userAgent:       ua,
		allowLoopback:   allowLoopback,
		allowPrivate:    allowPrivate,
		dialContext:     customDial,
		isAllowed:       isAllowed,
		isExcluded:      isExcluded,
	}
}

// SafeDialContext performs a safe, SSRF-protected TCP connection subject to scope rules.
func (c *Client) SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	targetURL := "tcp://" + addr
	if c.isExcluded != nil && (c.isExcluded(targetURL) || c.isExcluded(host)) {
		return nil, fmt.Errorf("connection to %s blocked: matches exclusion rule", addr)
	}
	if c.isAllowed != nil && !c.isAllowed(targetURL) && !c.isAllowed(host) && !c.isAllowed("http://"+addr) && !c.isAllowed("https://"+addr) {
		return nil, fmt.Errorf("connection to %s blocked: target outside authorized scope", addr)
	}

	if c.dialContext == nil {
		c.dialContext = crawler.NewSafeDialContext(crawler.SafeDialerOptions{
			Timeout:         c.timeout,
			AllowLoopback:   c.allowLoopback,
			AllowPrivateIPs: c.allowPrivate,
		})
	}

	return c.dialContext(ctx, network, addr)
}

// ProbeResponse captures bounded response metadata without storing uncontrolled payloads.
type ProbeResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Truncated  bool
}

// Do executes a bounded probe request subject to strict size and rate limits.
func (c *Client) Do(ctx context.Context, req *http.Request) (*ProbeResponse, error) {
	if req.URL != nil {
		reqURL := req.URL.String()
		if c.isExcluded != nil && c.isExcluded(reqURL) {
			return nil, fmt.Errorf("request to %s blocked: matches exclusion rule", reqURL)
		}
		if c.isAllowed != nil && !c.isAllowed(reqURL) {
			return nil, fmt.Errorf("request to %s blocked: target outside authorized scope", reqURL)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Rate limiting enforcement: Halt immediately on 429
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrRateLimited
	}

	// Size validation on Content-Length header
	if resp.ContentLength > c.maxResponseSize {
		return nil, ErrResponseTooLarge
	}

	// Bounded reading via io.LimitReader
	lr := io.LimitReader(resp.Body, c.maxResponseSize+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed reading response: %w", err)
	}

	truncated := false
	if int64(len(body)) > c.maxResponseSize {
		truncated = true
		body = body[:c.maxResponseSize]
	}

	return &ProbeResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Truncated:  truncated,
	}, nil
}
