package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// NewProvider instantiates the appropriate NotificationProvider based on providerType.
// Supported provider types: "webhook" (default), "slack", "discord", "teams".
func NewProvider(cfg WebhookConfig, providerType string) (NotificationProvider, error) {
	pType := strings.ToLower(strings.TrimSpace(providerType))
	switch pType {
	case "", "webhook":
		return NewWebhookProvider(cfg)
	case "slack":
		return NewSlackProvider(cfg)
	case "discord":
		return NewDiscordProvider(cfg)
	case "teams":
		return NewTeamsProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported notification provider %q (supported: webhook, slack, discord, teams)", providerType)
	}
}

// -----------------------------------------------------------------------------
// Slack Provider
// -----------------------------------------------------------------------------

// SlackProvider delivers notifications formatted as Slack Block Kit messages.
type SlackProvider struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewSlackProvider constructs a validated SlackProvider.
func NewSlackProvider(cfg WebhookConfig) (*SlackProvider, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	p := &SlackProvider{
		cfg:    cfg,
		client: newHardenedHTTPClient(cfg),
	}
	if err := p.ValidateConfig(); err != nil {
		return nil, err
	}
	return p, nil
}

// Name returns "slack".
func (p *SlackProvider) Name() string {
	return "slack"
}

// ValidateConfig verifies that the Slack webhook destination is safe and valid.
func (p *SlackProvider) ValidateConfig() error {
	trimmed := strings.TrimSpace(p.cfg.URL)
	if trimmed == "" {
		return errors.New("slack webhook URL cannot be empty")
	}
	ssrfCfg := SSRFConfig{
		AllowInsecureHTTP: p.cfg.AllowInsecureHTTP,
		AllowPrivateIPs:   p.cfg.AllowPrivateIPs,
		AllowLoopback:     p.cfg.AllowLoopback,
		MaxRedirects:      3,
		ResolveTimeout:    p.cfg.Timeout,
	}
	if _, err := ValidateEndpoint(trimmed, ssrfCfg); err != nil {
		return fmt.Errorf("invalid slack webhook configuration: %w", err)
	}
	return nil
}

// sanitizeSlackText neutralizes Slack mention injection (@channel, @everyone, @here, <!subteam>)
// and escapes user-controlled <, >, and & characters to prevent markup breakout.
func sanitizeSlackText(input string) string {
	s := secrets.RedactText(input)
	// Neutralize dangerous mentions by inserting zero-width spaces
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@channel", "@\u200bchannel")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	s = strings.ReplaceAll(s, "<!everyone>", "&lt;!everyone&gt;")
	s = strings.ReplaceAll(s, "<!channel>", "&lt;!channel&gt;")
	s = strings.ReplaceAll(s, "<!here>", "&lt;!here&gt;")
	s = strings.ReplaceAll(s, "<!subteam^", "&lt;!subteam^")
	s = strings.ReplaceAll(s, "<!date^", "&lt;!date^")
	s = strings.ReplaceAll(s, "<@", "&lt;@")
	return s
}

// Send formats and transmits a Slack Block Kit notification.
func (p *SlackProvider) Send(ctx context.Context, notif *Notification) (*DeliveryReceipt, error) {
	if notif == nil {
		return nil, &DeliveryError{Permanent: true, Message: "notification is nil"}
	}

	sanitizedTitle := sanitizeSlackText(notif.Title)
	sanitizedMsg := sanitizeSlackText(notif.Message)

	// Build Slack Block Kit payload
	headerText := sanitizedTitle
	if len(headerText) > 150 {
		headerText = headerText[:147] + "..."
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  headerText,
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": sanitizedMsg,
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Severity:*\n%s", notif.Severity),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Event:*\n%s", notif.EventType),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Findings:*\n%d", len(notif.FindingIDs)),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Delivery ID:*\n%s", notif.ID),
				},
			},
		},
	}

	slackPayload := map[string]interface{}{
		"text":   fmt.Sprintf("Felix Security: %s (%s)", sanitizedTitle, notif.Severity),
		"blocks": blocks,
	}

	bodyBytes, err := json.Marshal(slackPayload)
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to serialize slack payload: %v", err), Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to create request: %v", secrets.RedactText(err.Error())), Err: err}
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", DefaultWebhookUserAgent)
	req.Header.Set("X-Felix-Delivery", notif.ID)

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("slack request timeout or cancelled: %v", err), Err: err}
		}
		if errors.Is(err, ErrRedirectToUnsafeTarget) || errors.Is(err, ErrTooManyRedirects) || errors.Is(err, ErrSSRFDestinationBlocked) || errors.Is(err, ErrSSRFMetadataBlocked) {
			return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("security refusal: %v", err), Err: err}
		}
		return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("slack network delivery failure: %v", secrets.RedactText(err.Error())), Err: err}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	respStr := secrets.RedactText(strings.TrimSpace(string(respBody)))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &DeliveryReceipt{
			ReceiptID:    fmt.Sprintf("rcpt_slack_%s_%d", notif.ID, time.Now().UTC().Unix()),
			DeliveredAt:  time.Now().UTC(),
			StatusCode:   resp.StatusCode,
			ProviderName: p.Name(),
		}, nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return nil, &DeliveryError{
			Permanent:  true,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("slack rejected payload with HTTP %d: %s", resp.StatusCode, respStr),
		}
	}

	return nil, &DeliveryError{
		Permanent:  false,
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("slack returned transient HTTP %d: %s", resp.StatusCode, respStr),
	}
}

// -----------------------------------------------------------------------------
// Discord Provider
// -----------------------------------------------------------------------------

// DiscordProvider delivers notifications formatted for Discord webhooks with embedded cards.
type DiscordProvider struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewDiscordProvider constructs a validated DiscordProvider.
func NewDiscordProvider(cfg WebhookConfig) (*DiscordProvider, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	p := &DiscordProvider{
		cfg:    cfg,
		client: newHardenedHTTPClient(cfg),
	}
	if err := p.ValidateConfig(); err != nil {
		return nil, err
	}
	return p, nil
}

// Name returns "discord".
func (p *DiscordProvider) Name() string {
	return "discord"
}

// ValidateConfig verifies that the Discord webhook destination is safe and valid.
func (p *DiscordProvider) ValidateConfig() error {
	trimmed := strings.TrimSpace(p.cfg.URL)
	if trimmed == "" {
		return errors.New("discord webhook URL cannot be empty")
	}
	ssrfCfg := SSRFConfig{
		AllowInsecureHTTP: p.cfg.AllowInsecureHTTP,
		AllowPrivateIPs:   p.cfg.AllowPrivateIPs,
		AllowLoopback:     p.cfg.AllowLoopback,
		MaxRedirects:      3,
		ResolveTimeout:    p.cfg.Timeout,
	}
	if _, err := ValidateEndpoint(trimmed, ssrfCfg); err != nil {
		return fmt.Errorf("invalid discord webhook configuration: %w", err)
	}
	return nil
}

// sanitizeDiscordText neutralizes mass mentions (@everyone and @here) and user/role pings in Discord message text.
func sanitizeDiscordText(input string) string {
	s := secrets.RedactText(input)
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	s = strings.ReplaceAll(s, "<@&", "<@\u200b&")
	s = strings.ReplaceAll(s, "<@!", "<@\u200b!")
	s = strings.ReplaceAll(s, "<@", "<@\u200b")
	return s
}

// discordSeverityColor returns an RGB integer color corresponding to severity.
func discordSeverityColor(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return 15680580 // Red #EF4444
	case SeverityHigh:
		return 16347926 // Orange #F97316
	case SeverityMedium:
		return 16096779 // Yellow #F59E0B
	case SeverityLow:
		return 3900150 // Blue #3B82F6
	default:
		return 9741240 // Gray #94A3B8
	}
}

// Send formats and transmits a Discord embed notification.
func (p *DiscordProvider) Send(ctx context.Context, notif *Notification) (*DeliveryReceipt, error) {
	if notif == nil {
		return nil, &DeliveryError{Permanent: true, Message: "notification is nil"}
	}

	sanitizedTitle := sanitizeDiscordText(notif.Title)
	sanitizedMsg := sanitizeDiscordText(notif.Message)

	discordPayload := map[string]interface{}{
		"username": "Felix Security",
		// allowed_mentions: parse: [] strictly disables all role and user mentions at the API level
		"allowed_mentions": map[string]interface{}{
			"parse": []string{},
		},
		"embeds": []map[string]interface{}{
			{
				"title":       sanitizedTitle,
				"description": sanitizedMsg,
				"color":       discordSeverityColor(notif.Severity),
				"fields": []map[string]interface{}{
					{"name": "Severity", "value": notif.Severity, "inline": true},
					{"name": "Event", "value": notif.EventType, "inline": true},
					{"name": "Findings", "value": fmt.Sprintf("%d", len(notif.FindingIDs)), "inline": true},
				},
				"timestamp": notif.CreatedAt.UTC().Format(time.RFC3339),
				"footer": map[string]interface{}{
					"text": "Felix Security Auditor",
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(discordPayload)
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to serialize discord payload: %v", err), Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to create request: %v", secrets.RedactText(err.Error())), Err: err}
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", DefaultWebhookUserAgent)
	req.Header.Set("X-Felix-Delivery", notif.ID)

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("discord request timeout or cancelled: %v", err), Err: err}
		}
		if errors.Is(err, ErrRedirectToUnsafeTarget) || errors.Is(err, ErrTooManyRedirects) || errors.Is(err, ErrSSRFDestinationBlocked) || errors.Is(err, ErrSSRFMetadataBlocked) {
			return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("security refusal: %v", err), Err: err}
		}
		return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("discord network delivery failure: %v", secrets.RedactText(err.Error())), Err: err}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	respStr := secrets.RedactText(strings.TrimSpace(string(respBody)))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &DeliveryReceipt{
			ReceiptID:    fmt.Sprintf("rcpt_discord_%s_%d", notif.ID, time.Now().UTC().Unix()),
			DeliveredAt:  time.Now().UTC(),
			StatusCode:   resp.StatusCode,
			ProviderName: p.Name(),
		}, nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return nil, &DeliveryError{
			Permanent:  true,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("discord rejected payload with HTTP %d: %s", resp.StatusCode, respStr),
		}
	}

	return nil, &DeliveryError{
		Permanent:  false,
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("discord returned transient HTTP %d: %s", resp.StatusCode, respStr),
	}
}

// -----------------------------------------------------------------------------
// Microsoft Teams Provider
// -----------------------------------------------------------------------------

// TeamsProvider delivers notifications formatted as Microsoft Teams MessageCards.
type TeamsProvider struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewTeamsProvider constructs a validated TeamsProvider.
func NewTeamsProvider(cfg WebhookConfig) (*TeamsProvider, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	p := &TeamsProvider{
		cfg:    cfg,
		client: newHardenedHTTPClient(cfg),
	}
	if err := p.ValidateConfig(); err != nil {
		return nil, err
	}
	return p, nil
}

// Name returns "teams".
func (p *TeamsProvider) Name() string {
	return "teams"
}

// ValidateConfig verifies that the Teams webhook destination is safe and valid.
func (p *TeamsProvider) ValidateConfig() error {
	trimmed := strings.TrimSpace(p.cfg.URL)
	if trimmed == "" {
		return errors.New("teams webhook URL cannot be empty")
	}
	ssrfCfg := SSRFConfig{
		AllowInsecureHTTP: p.cfg.AllowInsecureHTTP,
		AllowPrivateIPs:   p.cfg.AllowPrivateIPs,
		AllowLoopback:     p.cfg.AllowLoopback,
		MaxRedirects:      3,
		ResolveTimeout:    p.cfg.Timeout,
	}
	if _, err := ValidateEndpoint(trimmed, ssrfCfg); err != nil {
		return fmt.Errorf("invalid teams webhook configuration: %w", err)
	}
	return nil
}

// teamsThemeColor returns a hex string color for the Teams MessageCard themeColor.
func teamsThemeColor(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return "EF4444"
	case SeverityHigh:
		return "F97316"
	case SeverityMedium:
		return "F59E0B"
	case SeverityLow:
		return "3B82F6"
	default:
		return "94A3B8"
	}
}

// sanitizeTeamsText neutralizes mention tags (<at>...</at>) and dangerous HTML markup in Teams message text.
func sanitizeTeamsText(input string) string {
	s := secrets.RedactText(input)
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@channel", "@\u200bchannel")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	s = strings.ReplaceAll(s, "<at>", "&lt;at&gt;")
	s = strings.ReplaceAll(s, "</at>", "&lt;/at&gt;")
	s = strings.ReplaceAll(s, "<script", "&lt;script")
	s = strings.ReplaceAll(s, "</script>", "&lt;/script&gt;")
	return s
}

// Send formats and transmits an Office 365 Connector / Teams MessageCard.
func (p *TeamsProvider) Send(ctx context.Context, notif *Notification) (*DeliveryReceipt, error) {
	if notif == nil {
		return nil, &DeliveryError{Permanent: true, Message: "notification is nil"}
	}

	sanitizedTitle := sanitizeTeamsText(notif.Title)
	sanitizedMsg := sanitizeTeamsText(notif.Message)

	teamsPayload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": teamsThemeColor(notif.Severity),
		"summary":    sanitizedTitle,
		"title":      sanitizedTitle,
		"sections": []map[string]interface{}{
			{
				"activityTitle":    sanitizedTitle,
				"activitySubtitle": fmt.Sprintf("Event: %s", notif.EventType),
				"text":             sanitizedMsg,
				"facts": []map[string]interface{}{
					{"name": "Severity", "value": notif.Severity},
					{"name": "Event Type", "value": notif.EventType},
					{"name": "Findings Count", "value": fmt.Sprintf("%d", len(notif.FindingIDs))},
					{"name": "Delivery ID", "value": notif.ID},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(teamsPayload)
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to serialize teams payload: %v", err), Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("failed to create request: %v", secrets.RedactText(err.Error())), Err: err}
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", DefaultWebhookUserAgent)
	req.Header.Set("X-Felix-Delivery", notif.ID)

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("teams request timeout or cancelled: %v", err), Err: err}
		}
		if errors.Is(err, ErrRedirectToUnsafeTarget) || errors.Is(err, ErrTooManyRedirects) || errors.Is(err, ErrSSRFDestinationBlocked) || errors.Is(err, ErrSSRFMetadataBlocked) {
			return nil, &DeliveryError{Permanent: true, Message: fmt.Sprintf("security refusal: %v", err), Err: err}
		}
		return nil, &DeliveryError{Permanent: false, Message: fmt.Sprintf("teams network delivery failure: %v", secrets.RedactText(err.Error())), Err: err}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	respStr := secrets.RedactText(strings.TrimSpace(string(respBody)))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &DeliveryReceipt{
			ReceiptID:    fmt.Sprintf("rcpt_teams_%s_%d", notif.ID, time.Now().UTC().Unix()),
			DeliveredAt:  time.Now().UTC(),
			StatusCode:   resp.StatusCode,
			ProviderName: p.Name(),
		}, nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return nil, &DeliveryError{
			Permanent:  true,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("teams rejected payload with HTTP %d: %s", resp.StatusCode, respStr),
		}
	}

	return nil, &DeliveryError{
		Permanent:  false,
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("teams returned transient HTTP %d: %s", resp.StatusCode, respStr),
	}
}
