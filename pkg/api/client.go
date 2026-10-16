package api

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

var (
	ErrRateLimited      = errors.New("rate limited by target (HTTP 429)")
	ErrResponseTooLarge = errors.New("API response exceeds size limit")
)

const (
	DefaultAPITimeout     = 8 * time.Second
	DefaultMaxAPIResponse = 1024 * 1024 // 1 MB limit for safe probing
	DefaultUserAgent      = "Felix/0.1 (Defensive API Security Auditor)"
)

// ClientOptions configures the safe API probe client.
type ClientOptions struct {
	Timeout         time.Duration
	MaxResponseSize int64
	UserAgent       string
	HTTPClient      *http.Client
	AllowLoopback   bool
	AllowPrivateIPs bool
	RateLimit       float64
	MaxConcurrency  int
	IsAllowed       func(string) bool
	IsExcluded      func(string) bool
}

// Client manages bounded HTTP requests for API auditing.
type Client struct {
	httpClient      *http.Client
	timeout         time.Duration
	maxResponseSize int64
	userAgent       string
	isAllowed       func(string) bool
	isExcluded      func(string) bool
}

// NewClient initializes a hardened API client with scope-bounded redirect handling.
func NewClient(opts ...ClientOptions) *Client {
	timeout := DefaultAPITimeout
	maxSize := int64(DefaultMaxAPIResponse)
	ua := DefaultUserAgent
	var customHTTP *http.Client
	var allowLoopback bool
	var allowPrivate bool
	var isAllowed func(string) bool
	var isExcluded func(string) bool

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
		isAllowed = opts[0].IsAllowed
		isExcluded = opts[0].IsExcluded
	}

	if customHTTP == nil {
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:         timeout,
			AllowLoopback:   allowLoopback,
			AllowPrivateIPs: allowPrivate,
		})
		var rateVal float64
		var concVal int
		if len(opts) > 0 {
			rateVal = opts[0].RateLimit
			concVal = opts[0].MaxConcurrency
		}
		transport := crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{
			Rate:           rateVal,
			MaxConcurrency: concVal,
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
				// Prevent cross-origin redirect following to enforce scope boundaries
				if len(via) > 0 {
					origHost := via[0].URL.Host
					if req.URL.Host != origHost {
						return http.ErrUseLastResponse
					}
				}
				return nil
			},
		}
	} else {
		// Custom HTTP client provided: ensure underlying transport cannot bypass SSRF protections or rate limiting
		if customHTTP.Transport == nil {
			customHTTP.Transport = crawler.NewSafeTransport(crawler.SafeTransportOptions{
				Timeout:         timeout,
				AllowLoopback:   allowLoopback,
				AllowPrivateIPs: allowPrivate,
			})
		}
		if _, ok := customHTTP.Transport.(*crawler.RateLimitedTransport); !ok {
			var rateVal float64
			var concVal int
			if len(opts) > 0 {
				rateVal = opts[0].RateLimit
				concVal = opts[0].MaxConcurrency
			}
			customHTTP.Transport = crawler.NewRateLimitedTransport(customHTTP.Transport, crawler.RateLimitOptions{
				Rate:           rateVal,
				MaxConcurrency: concVal,
			})
		}
		if customHTTP.CheckRedirect == nil {
			customHTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
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
				return nil
			}
		}
	}

	return &Client{
		httpClient:      customHTTP,
		timeout:         timeout,
		maxResponseSize: maxSize,
		userAgent:       ua,
		isAllowed:       isAllowed,
		isExcluded:      isExcluded,
	}
}

// ProbeResponse captures bounded response data.
type ProbeResponse struct {
	StatusCode        int
	Header            http.Header
	Body              []byte
	Truncated         bool
	Redirected        bool
	RedirectURL       string
	InitialStatusCode int
}

// DoBounded executes a request with an explicit maximum response size limit (e.g. 512 KiB for Actuator auditing).
func (c *Client) DoBounded(ctx context.Context, req *http.Request, maxBytes int64) (*ProbeResponse, error) {
	effectiveLimit := c.maxResponseSize
	if maxBytes > 0 && maxBytes < effectiveLimit {
		effectiveLimit = maxBytes
	}

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

	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	resp, err := c.httpClient.Do(req.WithContext(reqCtx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	redirected := false
	redirectURL := ""
	initialStatus := resp.StatusCode
	if resp.Request != nil && resp.Request.Response != nil {
		redirected = true
		redirectURL = resp.Request.URL.String()
		initialStatus = resp.Request.Response.StatusCode
	}

	// Rate limiting: halt immediately on 429
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrRateLimited
	}

	// Size limit validation on Content-Length header
	if resp.ContentLength > effectiveLimit {
		return nil, ErrResponseTooLarge
	}

	// Bounded read via io.LimitReader
	lr := io.LimitReader(resp.Body, effectiveLimit+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed reading response: %w", err)
	}

	truncated := false
	if int64(len(body)) > effectiveLimit {
		truncated = true
		body = body[:effectiveLimit]
	}

	return &ProbeResponse{
		StatusCode:        resp.StatusCode,
		Header:            resp.Header,
		Body:              body,
		Truncated:         truncated,
		Redirected:        redirected,
		RedirectURL:       redirectURL,
		InitialStatusCode: initialStatus,
	}, nil
}

// Do executes a bounded request subject to size limits, rate limiting, and scope preservation.
func (c *Client) Do(ctx context.Context, req *http.Request) (*ProbeResponse, error) {
	return c.DoBounded(ctx, req, c.maxResponseSize)
}
