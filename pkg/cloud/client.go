package cloud

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
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
}

// Client manages safe, bounded outbound HTTP requests for cloud service verification.
type Client struct {
	httpClient      *http.Client
	timeout         time.Duration
	maxResponseSize int64
	userAgent       string
}

// NewClient initializes a hardened, bounded probe client.
func NewClient(opts ...ClientOptions) *Client {
	timeout := DefaultProbeTimeout
	maxSize := int64(DefaultMaxCloudResponse)
	ua := DefaultUserAgent
	var customHTTP *http.Client

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
	}

	if customHTTP == nil {
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          50,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		customHTTP = &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
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
	}
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
