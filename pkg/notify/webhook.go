package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/secrets"
)

const (
	DefaultWebhookTimeout    = 10 * time.Second
	DefaultMaxPayloadBytes   = 256 * 1024 // 256 KB
	DefaultWebhookUserAgent  = "Felix-Notifier/1.0 (+https://github.com/jothish-blip/felix)"
)

// WebhookConfig contains settings for the Webhook notification provider.
type WebhookConfig struct {
	URL                string
	Secret             string        // HMAC-SHA256 secret key for request signature verification
	PreviousSecret     string        // Optional previous HMAC secret during key rotation window
	RequireSigning     bool          // If true, deliveries MUST be signed; fails closed if secret is empty
	SignatureVersion   string        // Signature version (default "v1", supports "legacy" or "sha256")
	SignatureTolerance time.Duration // Timestamp tolerance window (default 300s)
	Timeout            time.Duration
	AllowInsecureHTTP  bool
	AllowPrivateIPs    bool
	AllowLoopback      bool
	MaxPayloadBytes    int
	HTTPClient         *http.Client // Optional custom client (used in tests)
}

// WebhookProvider implements NotificationProvider via HTTP POST.
type WebhookProvider struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhookProvider constructs a configured WebhookProvider with DNS rebinding & SSRF immunity.
func NewWebhookProvider(cfg WebhookConfig) (*WebhookProvider, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = DefaultMaxPayloadBytes
	}

	p := &WebhookProvider{
		cfg:    cfg,
		client: newHardenedHTTPClient(cfg),
	}

	if err := p.ValidateConfig(); err != nil {
		return nil, err
	}

	return p, nil
}

// newHardenedHTTPClient constructs a hardened HTTP client with connection-time DNS verification
// to eliminate SSRF, DNS rebinding, and TOCTOU vulnerabilities across all notification providers.
func newHardenedHTTPClient(cfg WebhookConfig) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}

	ssrfCfg := SSRFConfig{
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
		AllowPrivateIPs:   cfg.AllowPrivateIPs,
		AllowLoopback:     cfg.AllowLoopback,
		MaxRedirects:      3,
		ResolveTimeout:    cfg.Timeout,
	}

	// Hardened HTTP transport with connection-time DNS verification
	// to eliminate DNS rebinding and TOCTOU security gaps.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Resolve target host
			var ips []net.IP
			if ipLit := net.ParseIP(host); ipLit != nil {
				ips = []net.IP{ipLit}
			} else {
				resolver := &net.Resolver{}
				var lErr error
				ips, lErr = resolver.LookupIP(ctx, "ip", host)
				if lErr != nil {
					return nil, fmt.Errorf("failed to resolve %s: %w", secrets.RedactText(host), lErr)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for %s", secrets.RedactText(host))
			}

			// Check each resolved IP address right before socket connection.
			// Fail-closed security rule: ALL resolved IPs must be permitted.
			// If a dual-homed host or DNS rebinding attempt resolves to any prohibited IP, reject!
			for _, ip := range ips {
				if vErr := ValidateIP(ip, cfg.AllowPrivateIPs, cfg.AllowLoopback); vErr != nil {
					return nil, fmt.Errorf("%w: destination %s resolved to prohibited IP %s: %v", ErrSSRFDestinationBlocked, secrets.RedactText(host), ip.String(), vErr)
				}
			}
			safeIP := ips[0]

			dialer := &net.Dialer{
				Timeout:   cfg.Timeout,
				KeepAlive: 30 * time.Second,
			}
			// Dial the verified safe IP; TLS handshake will still use SNI from req.URL.Hostname()
			return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= ssrfCfg.MaxRedirects {
				return ErrTooManyRedirects
			}
			// Verify destination URL on each redirect hop
			if _, err := ValidateEndpoint(req.URL.String(), ssrfCfg); err != nil {
				return fmt.Errorf("%w: %v", ErrRedirectToUnsafeTarget, err)
			}
			// Security hardening: strip sensitive headers on cross-origin redirects
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del(HeaderFelixSignature)
				req.Header.Del(HeaderFelixTimestamp)
				req.Header.Del(HeaderFelixDelivery)
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
			}
			return nil
		},
	}
}

// Name returns "webhook".
func (p *WebhookProvider) Name() string {
	return "webhook"
}

// ValidateConfig checks URL validity, protocol schemes, SSRF rules, and mandatory signing keys.
func (p *WebhookProvider) ValidateConfig() error {
	if p.cfg.RequireSigning && strings.TrimSpace(p.cfg.Secret) == "" {
		return fmt.Errorf("invalid webhook configuration: %w", ErrSigningKeyRequired)
	}

	trimmed := strings.TrimSpace(p.cfg.URL)
	if trimmed == "" {
		return errors.New("webhook URL cannot be empty")
	}

	ssrfCfg := SSRFConfig{
		AllowInsecureHTTP: p.cfg.AllowInsecureHTTP,
		AllowPrivateIPs:   p.cfg.AllowPrivateIPs,
		AllowLoopback:     p.cfg.AllowLoopback,
		MaxRedirects:      3,
		ResolveTimeout:    p.cfg.Timeout,
	}

	_, err := ValidateEndpoint(trimmed, ssrfCfg)
	if err != nil {
		return fmt.Errorf("invalid webhook configuration: %w", err)
	}

	return nil
}

// Send delivers a notification to the configured webhook endpoint.
func (p *WebhookProvider) Send(ctx context.Context, notif *Notification) (*DeliveryReceipt, error) {
	if notif == nil {
		return nil, &DeliveryError{Permanent: true, Message: "notification is nil"}
	}

	// 1. Mandatory signing enforcement: fail closed if signing required but no key configured
	if p.cfg.RequireSigning && strings.TrimSpace(p.cfg.Secret) == "" {
		return nil, &DeliveryError{
			Permanent: true,
			Message:   "signing is required by configuration, but no webhook secret is configured",
			Err:       ErrSigningKeyRequired,
		}
	}

	payload := notif.ToWebhookPayload()
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to serialize payload: %v", err), Err: err}
	}

	// Bounded payload size check
	if len(bodyBytes) > p.cfg.MaxPayloadBytes {
		// Truncate finding IDs to fit bounds while preserving metadata
		if len(payload.FindingIDs) > 10 {
			payload.FindingIDs = payload.FindingIDs[:10]
			payload.Metadata["truncated_findings"] = true
			if reencoded, reErr := json.Marshal(payload); reErr == nil && len(reencoded) <= p.cfg.MaxPayloadBytes {
				bodyBytes = reencoded
			} else {
				return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("payload exceeds maximum permitted size (%d > %d bytes)", len(bodyBytes), p.cfg.MaxPayloadBytes)}
			}
		} else {
			return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("payload exceeds maximum permitted size (%d > %d bytes)", len(bodyBytes), p.cfg.MaxPayloadBytes)}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to create request: %v", secrets.RedactText(err.Error())), Err: err}
	}

	nowUnix := time.Now().UTC().Unix()
	timestampStr := fmt.Sprintf("%d", nowUnix)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", DefaultWebhookUserAgent)
	req.Header.Set("X-Felix-Event", notif.EventType)
	req.Header.Set("X-Felix-Delivery", notif.ID) // Stable delivery ID across retries
	req.Header.Set("X-Felix-Timestamp", timestampStr)

	// HMAC-SHA256 signature if secret is provided
	if strings.TrimSpace(p.cfg.Secret) != "" {
		if strings.EqualFold(p.cfg.SignatureVersion, "sha256") || strings.EqualFold(p.cfg.SignatureVersion, "legacy") {
			legacySig := ComputeWebhookSignature(p.cfg.Secret, bodyBytes)
			req.Header.Set("X-Felix-Signature", fmt.Sprintf("sha256=%s", legacySig))
		} else {
			sigV1 := ComputeSignatureV1(p.cfg.Secret, timestampStr, bodyBytes)
			var sigParts []string
			sigParts = append(sigParts, fmt.Sprintf("v1=%s", sigV1))

			// Key rotation support: also append signature for previous secret if configured
			if strings.TrimSpace(p.cfg.PreviousSecret) != "" {
				sigPrev := ComputeSignatureV1(p.cfg.PreviousSecret, timestampStr, bodyBytes)
				sigParts = append(sigParts, fmt.Sprintf("v1=%s", sigPrev))
			}
			req.Header.Set("X-Felix-Signature", strings.Join(sigParts, ","))
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		// Check context timeout or cancellation
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &DeliveryError{
				Permanent: false,
				Message:   fmt.Sprintf("webhook request timeout or cancelled: %v", err),
				Err:       err,
			}
		}

		// Check for SSRF or redirect errors
		if errors.Is(err, ErrRedirectToUnsafeTarget) || errors.Is(err, ErrTooManyRedirects) || errors.Is(err, ErrSSRFDestinationBlocked) || errors.Is(err, ErrSSRFMetadataBlocked) {
			return nil, &DeliveryError{
				Permanent: true,
				Message:   fmt.Sprintf("security refusal: %v", err),
				Err:       err,
			}
		}

		// Transient network failures
		return nil, &DeliveryError{
			Permanent: false,
			Message:   fmt.Sprintf("network delivery failure: %v", secrets.RedactText(err.Error())),
			Err:       err,
		}
	}
	defer resp.Body.Close()

	// Drain up to 4KB of response body for logging/debugging without reading unbounded responses
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	respStr := secrets.RedactText(strings.TrimSpace(string(respBody)))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		receiptID := resp.Header.Get("X-Delivery-Receipt")
		if receiptID == "" {
			receiptID = fmt.Sprintf("rcpt_%s_%d", notif.ID, time.Now().UTC().Unix())
		}
		return &DeliveryReceipt{
			ReceiptID:    receiptID,
			DeliveredAt:  time.Now().UTC(),
			StatusCode:   resp.StatusCode,
			ProviderName: p.Name(),
		}, nil
	}

	// Permanent failures (4xx except 429)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return nil, &DeliveryError{
			Permanent:  true,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("webhook destination rejected payload with HTTP %d: %s", resp.StatusCode, respStr),
		}
	}

	// Transient server errors (429, 5xx)
	return nil, &DeliveryError{
		Permanent:  false,
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("webhook destination returned transient HTTP %d: %s", resp.StatusCode, respStr),
	}
}

// ComputeWebhookSignature computes HMAC-SHA256 signature for verification testing.
func ComputeWebhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// SafeWebhookURL returns a sanitized display string for a webhook URL (redacting query params).
func SafeWebhookURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return secrets.RedactText(rawURL)
	}
	if u.RawQuery != "" {
		u.RawQuery = "[REDACTED]"
	}
	if u.User != nil {
		u.User = url.User("[REDACTED]")
	}
	return u.String()
}
