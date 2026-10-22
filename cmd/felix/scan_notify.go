package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// scanNotifyOptions holds CLI parameters for assessment notification dispatch.
type scanNotifyOptions struct {
	enabled        bool
	explicit       bool
	webhookURL     string
	provider       string
	secret         string
	previousSecret string
	requireSigning bool
	minSeverity    string
	allowPrivate   bool
	allowLoopback  bool
	insecure       bool
	quiet          bool
}

// resolveNotifySecret resolves the secret value safely, preferring environment variable references
// (such as env:VAR_NAME or $VAR_NAME) or FELIX_NOTIFY_SECRET / FELIX_NOTIFY_WEBHOOK_SECRET
// to avoid leaking credentials via process listings (ps aux) or shell history.
func resolveNotifySecret(val string, cfgSecret string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "env:") {
		envKey := strings.TrimPrefix(val, "env:")
		return os.Getenv(envKey)
	}
	if strings.HasPrefix(val, "$") && !strings.Contains(val, " ") {
		envKey := strings.TrimPrefix(val, "$")
		return os.Getenv(envKey)
	}
	if val != "" {
		return val
	}
	if envVal := os.Getenv("FELIX_NOTIFY_SECRET"); envVal != "" {
		return envVal
	}
	if envVal := os.Getenv("FELIX_NOTIFY_WEBHOOK_SECRET"); envVal != "" {
		return envVal
	}
	return cfgSecret
}

// resolvePreviousSecret resolves the previous HMAC secret value safely for key rotation.
func resolvePreviousSecret(val string, cfgSecret string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "env:") {
		envKey := strings.TrimPrefix(val, "env:")
		return os.Getenv(envKey)
	}
	if strings.HasPrefix(val, "$") && !strings.Contains(val, " ") {
		envKey := strings.TrimPrefix(val, "$")
		return os.Getenv(envKey)
	}
	if val != "" {
		return val
	}
	if envVal := os.Getenv("FELIX_NOTIFY_PREVIOUS_SECRET"); envVal != "" {
		return envVal
	}
	return cfgSecret
}

// dispatchReportNotification delivers a notification built from a canonical Report.
// Under all circumstances, errors are logged but NEVER modify assessment outcomes or exit codes.
func dispatchReportNotification(rep report.Report, cfgStore config.Config, opts scanNotifyOptions) {
	if !opts.enabled {
		return
	}

	targetURL := opts.webhookURL
	if targetURL == "" {
		targetURL = cfgStore.Notification.WebhookURL
	}
	if targetURL == "" {
		if opts.explicit {
			fmt.Fprintln(os.Stderr, "[-] Notification requested (--notify) but no webhook URL specified (use --webhook <url> or set webhook_url in config)")
		}
		return
	}

	providerType := opts.provider
	if providerType == "" {
		providerType = cfgStore.Notification.Provider
	}
	if providerType == "" {
		providerType = "webhook"
	}

	secret := resolveNotifySecret(opts.secret, cfgStore.Notification.WebhookSecret)
	prevSecret := resolvePreviousSecret(opts.previousSecret, cfgStore.Notification.WebhookPreviousSecret)
	requireSigning := opts.requireSigning || cfgStore.Notification.RequireSigning

	minSev := opts.minSeverity
	if minSev == "" && !opts.explicit {
		minSev = cfgStore.Notification.MinSeverity
	}

	notif := notify.BuildReportNotification(rep, rep.Target, "", time.Now().UTC())
	if minSev != "" && !notify.MeetsSeverityThreshold(notif.Severity, minSev) {
		return
	}

	timeout := 10 * time.Second
	if cfgStore.Notification.TimeoutSeconds > 0 {
		timeout = time.Duration(cfgStore.Notification.TimeoutSeconds) * time.Second
	}

	insecureAllowed := cfgStore.Notification.AllowInsecureHTTP || opts.insecure
	loopbackAllowed := cfgStore.Notification.AllowLoopback || opts.allowLoopback
	if (strings.HasPrefix(targetURL, "http://127.0.0.1") || strings.HasPrefix(targetURL, "http://localhost")) && loopbackAllowed {
		insecureAllowed = true
	}

	sigTolerance := time.Duration(cfgStore.Notification.SignatureToleranceSeconds) * time.Second
	if sigTolerance <= 0 {
		sigTolerance = notify.DefaultSignatureTolerance
	}

	webhookCfg := notify.WebhookConfig{
		URL:                targetURL,
		Secret:             secret,
		PreviousSecret:     prevSecret,
		RequireSigning:     requireSigning,
		SignatureTolerance: sigTolerance,
		Timeout:            timeout,
		AllowInsecureHTTP:  insecureAllowed,
		AllowPrivateIPs:    cfgStore.Notification.AllowPrivateIPs || opts.allowPrivate,
		AllowLoopback:      loopbackAllowed,
	}

	provider, err := notify.NewProvider(webhookCfg, providerType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Notification error: invalid provider configuration: %v\n", secrets.RedactText(err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
	defer cancel()

	maxRetries := cfgStore.Notification.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 2
	}

	receipt, err := notify.SendWithRetries(ctx, provider, notif, maxRetries, 200*time.Millisecond)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Notification delivery failed: %v\n", secrets.RedactText(err.Error()))
		return
	}

	if !opts.quiet {
		fmt.Printf("[✓] Notification delivered via %s (status %d, receipt %s)\n", provider.Name(), receipt.StatusCode, receipt.ReceiptID)
	}

	// Also emit dedicated critical finding alerts when critical findings are discovered
	if rep.Summary.CriticalCount > 0 {
		for _, f := range rep.Findings {
			if strings.ToUpper(f.Severity) == notify.SeverityCritical {
				critNotif := notify.BuildCriticalFindingNotification(
					"default", "", "", rep.Target, "",
					f, time.Now().UTC(),
				)
				_, _ = notify.SendWithRetries(ctx, provider, critNotif, maxRetries, 200*time.Millisecond)
			}
		}
	}
}
