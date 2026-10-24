package monitor

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/notify"
	"felix/pkg/secrets"
)

// DeliverySummary aggregates results of an alerting pass across all configured webhooks.
type DeliverySummary struct {
	TotalEventsEvaluated int      `json:"total_events_evaluated"`
	TotalAttempted       int      `json:"total_attempted"`
	TotalDelivered       int      `json:"total_delivered"`
	TotalSkippedDedupe   int      `json:"total_skipped_dedupe"`
	TotalFailed          int      `json:"total_failed"`
	Warnings             []string `json:"warnings,omitempty"`
}

// Notifier coordinates secure, deduplicated alert dispatch to external channels (Slack, Discord, Teams).
type Notifier struct {
	cfg           *api.MonitoringConfig
	deliveryStore *DeliveryStateStore
}

// NewNotifier initializes a Notifier bound to target monitoring settings and delivery state.
func NewNotifier(cfg *api.MonitoringConfig, deliveryStore *DeliveryStateStore) *Notifier {
	return &Notifier{
		cfg:           cfg,
		deliveryStore: deliveryStore,
	}
}

// DeliverAlerts dispatches qualifying drift events to configured webhook destinations.
func (n *Notifier) DeliverAlerts(ctx context.Context, rep *DriftReport) (*DeliverySummary, error) {
	summary := &DeliverySummary{
		TotalEventsEvaluated: len(rep.Events),
	}

	if n.cfg == nil || !n.cfg.Enabled || len(n.cfg.Webhooks) == 0 {
		return summary, nil
	}

	// Build notification filter set
	notifyFilter := make(map[string]bool)
	for _, f := range n.cfg.NotifyOn {
		notifyFilter[strings.ToUpper(strings.TrimSpace(f))] = true
	}

	for _, wh := range n.cfg.Webhooks {
		if !wh.Enabled {
			continue
		}

		// Resolve destination URL
		destURL := strings.TrimSpace(wh.URL)
		if destURL == "" && wh.CredentialEnv != "" {
			destURL = strings.TrimSpace(os.Getenv(wh.CredentialEnv))
		}
		if destURL == "" {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("Webhook %q skipped: credential environment variable %s is not set", wh.ID, wh.CredentialEnv))
			continue
		}

		// Validate URL and security boundaries
		provider, err := n.buildValidatedProvider(wh, destURL)
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("Webhook %q validation failed: %v", wh.ID, err))
			continue
		}

		// Iterate through events and dispatch
		for _, evt := range rep.Events {
			if ctx.Err() != nil {
				return summary, ctx.Err()
			}

			// Do not alert on baseline initialization or purely informational baseline status
			if evt.Classification == ClassificationBaselineMissing {
				continue
			}

			// Apply notify_on filter if configured
			if len(notifyFilter) > 0 && !notifyFilter[string(evt.Classification)] {
				continue
			}

			// Check deduplication
			if n.deliveryStore != nil && n.deliveryStore.IsDelivered(wh.ID, evt.ID) {
				summary.TotalSkippedDedupe++
				continue
			}

			// Build safe notification payload
			notif := n.buildNotificationFromEvent(rep.TargetID, evt)
			summary.TotalAttempted++

			// Dispatch with bounded retry
			receipt, err := n.dispatchWithRetry(ctx, provider, notif)
			if err != nil {
				summary.TotalFailed++
				summary.Warnings = append(summary.Warnings, fmt.Sprintf("Delivery to %s (%s) failed: %v", wh.ID, wh.Provider, secrets.RedactText(err.Error())))
				if n.deliveryStore != nil {
					isPerm := false
					var delivErr *notify.DeliveryError
					if errors.As(err, &delivErr) {
						isPerm = delivErr.IsPermanent()
					}
					_ = n.deliveryStore.RecordDeliveryFailure(wh.ID, evt.ID, wh.Provider, err.Error(), isPerm)
				}
			} else {
				summary.TotalDelivered++
				if n.deliveryStore != nil {
					_ = n.deliveryStore.RecordDeliverySuccess(wh.ID, evt.ID, wh.Provider, receipt.ReceiptID, receipt.DeliveredAt)
				}
			}
		}
	}

	return summary, nil
}

// SendTestWebhook delivers a clearly marked synthetic verification message.
func (n *Notifier) SendTestWebhook(ctx context.Context, webhookID string, targetProvider string) (*notify.DeliveryReceipt, error) {
	if n.cfg == nil || len(n.cfg.Webhooks) == 0 {
		return nil, errors.New("no webhooks configured in monitoring profile")
	}

	var targetWh *api.MonitorWebhookConfig
	for _, wh := range n.cfg.Webhooks {
		if webhookID != "" && wh.ID == webhookID {
			targetWh = &wh
			break
		}
		if targetProvider != "" && strings.EqualFold(wh.Provider, targetProvider) {
			targetWh = &wh
			break
		}
	}

	if targetWh == nil {
		if webhookID != "" {
			return nil, fmt.Errorf("configured webhook %q not found in profile", webhookID)
		}
		if targetProvider != "" {
			return nil, fmt.Errorf("no webhook configured with provider %q", targetProvider)
		}
		targetWh = &n.cfg.Webhooks[0]
	}

	destURL := strings.TrimSpace(targetWh.URL)
	if destURL == "" && targetWh.CredentialEnv != "" {
		destURL = strings.TrimSpace(os.Getenv(targetWh.CredentialEnv))
	}
	if destURL == "" {
		return nil, fmt.Errorf("webhook credential environment variable %s is not set", targetWh.CredentialEnv)
	}

	provider, err := n.buildValidatedProvider(*targetWh, destURL)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	testNotif := &notify.Notification{
		ID:        fmt.Sprintf("test_%d", now.UnixNano()),
		EventType: "monitor.test",
		Severity:  "INFO",
		Title:     "[SYNTHETIC TEST] Felix Security Monitor Alerting Verification",
		Message:   fmt.Sprintf("This is an authorized synthetic test message from Felix Security Monitor to verify delivery to provider %q. No assessment data was transmitted.\nTimestamp: %s", targetWh.Provider, now.Format(time.RFC3339)),
		CreatedAt: now,
	}

	return provider.Send(ctx, testNotif)
}

// buildValidatedProvider enforces HTTPS, SSRF constraints, and instantiates the provider.
func (n *Notifier) buildValidatedProvider(wh api.MonitorWebhookConfig, destURL string) (notify.NotificationProvider, error) {
	u, err := url.Parse(destURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid webhook destination URL %q", destURL)
	}

	// Enforce HTTPS unless explicitly allowed in test configuration
	if strings.ToLower(u.Scheme) != "https" && !wh.AllowInsecureHTTP {
		return nil, fmt.Errorf("insecure webhook destination scheme %q strictly forbidden; HTTPS is required", u.Scheme)
	}

	provType := strings.ToLower(strings.TrimSpace(wh.Provider))
	if provType == "" {
		provType = "slack"
	}

	webhookCfg := notify.WebhookConfig{
		URL:               destURL,
		Timeout:           8 * time.Second,
		AllowInsecureHTTP: wh.AllowInsecureHTTP,
		AllowLoopback:     wh.AllowLoopback,
		AllowPrivateIPs:   wh.AllowPrivateIPs,
	}

	return notify.NewProvider(webhookCfg, provType)
}

// buildNotificationFromEvent formats a sanitized, operator-actionable notification payload.
func (n *Notifier) buildNotificationFromEvent(targetID string, evt DriftEvent) *notify.Notification {
	routeText := evt.CanonicalRoute
	if evt.Method != "" {
		routeText = fmt.Sprintf("%s %s", evt.Method, evt.CanonicalRoute)
	}

	title := fmt.Sprintf("[%s] %s: %s", evt.Priority, evt.Classification, routeText)
	if len(title) > 120 {
		title = title[:117] + "..."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*Target:* %s\n", targetID))
	sb.WriteString(fmt.Sprintf("*Route:* %s\n", routeText))
	sb.WriteString(fmt.Sprintf("*Classification:* %s (Priority: %s)\n", evt.Classification, evt.Priority))
	sb.WriteString(fmt.Sprintf("*Rationale:* %s\n", evt.PriorityRationale))

	if evt.PreviousValue != "" && evt.CurrentValue != "" {
		sb.WriteString(fmt.Sprintf("*Observation Shift:* %s -> %s\n", evt.PreviousValue, evt.CurrentValue))
	}
	if len(evt.SensitiveIdentifiers) > 0 {
		sb.WriteString(fmt.Sprintf("*Sensitive Boundary:* %s\n", strings.Join(evt.SensitiveIdentifiers, ", ")))
	}
	if evt.SuggestedAction != "" {
		sb.WriteString(fmt.Sprintf("*Action Required:* %s\n", evt.SuggestedAction))
	}
	sb.WriteString(fmt.Sprintf("*Event ID:* %s", evt.ID))

	sanitizedMsg := secrets.RedactText(sb.String())

	return &notify.Notification{
		ID:             evt.ID,
		TenantID:       targetID,
		EventType:      fmt.Sprintf("monitor.drift.%s", strings.ToLower(string(evt.Classification))),
		Severity:       string(evt.Priority),
		Title:          title,
		Message:        sanitizedMsg,
		Classification: string(evt.Classification),
		DedupKey:       evt.ID,
		CreatedAt:      evt.DetectedAt,
	}
}

// dispatchWithRetry dispatches a notification with bounded backoff on transient errors.
func (n *Notifier) dispatchWithRetry(ctx context.Context, provider notify.NotificationProvider, notif *notify.Notification) (*notify.DeliveryReceipt, error) {
	maxAttempts := 3
	backoff := 500 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		receipt, err := provider.Send(ctx, notif)
		if err == nil {
			return receipt, nil
		}

		lastErr = err
		var delivErr *notify.DeliveryError
		if errors.As(err, &delivErr) && delivErr.IsPermanent() {
			// Permanent failure (e.g. 400 Bad Request, 401 Unauthorized, SSRF security block) -> abort retry
			return nil, lastErr
		}

		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}

	return nil, lastErr
}
