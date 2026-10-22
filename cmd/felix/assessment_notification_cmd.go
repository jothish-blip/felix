package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/secrets"
)

func runAssessmentNotification(args []string) int {
	return runNotification(args)
}

func runNotification(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printNotificationHelp()
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "status":
		return runNotificationStatus(subArgs)
	case "list", "ls":
		return runNotificationList(subArgs)
	case "show", "get", "inspect":
		return runNotificationShow(subArgs)
	case "retry", "requeue":
		return runNotificationRetry(subArgs)
	case "test", "ping":
		return runNotificationTest(subArgs)
	case "dispatch", "send", "flush":
		return runNotificationDispatch(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown notification subcommand: %s\n\n", sub)
		printNotificationHelp()
		return 2
	}
}

func printNotificationHelp() {
	fmt.Println("Usage: felix notification <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  status      Display notification subsystem configuration and health")
	fmt.Println("  list        List notification outbox records")
	fmt.Println("  show        Inspect a specific notification record and delivery state")
	fmt.Println("  retry       Reset a failed notification to pending for retry")
	fmt.Println("  test        Send an explicit test notification ping to verify endpoint")
	fmt.Println("  dispatch    Process and deliver pending outbox notifications")
	fmt.Println("\nRun 'felix notification <subcommand> --help' for flags.")
}

func runNotificationStatus(args []string) int {
	var asJSON bool
	var dbPath string
	var (
		role      string
		clientID  string
		tenantID  string
		accountID string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--help", "-h", "help":
			fmt.Println("Usage: felix notification status [--json] [--tenant <id>] [--db <path>]")
			return 0
		}
	}

	cfg, _ := config.LoadWithEnv("")

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	var stats *notify.SubsystemStats
	store, err := assessment.NewSQLiteStore(dbPath)
	if err == nil {
		defer store.Close()
		stats, _ = store.GetNotificationStats(auth)
	}

	if asJSON {
		secretDisplay := "[NOT SET]"
		if cfg.Notification.WebhookSecret != "" {
			secretDisplay = "[CONFIGURED]"
		}
		webhookURLDisplay := notify.SafeWebhookURL(cfg.Notification.WebhookURL)
		if !auth.IsAdmin() {
			webhookURLDisplay = "[REDACTED - ADMIN ONLY]"
			secretDisplay = "[REDACTED - ADMIN ONLY]"
		}
		data := map[string]interface{}{
			"enabled":            cfg.Notification.Enabled,
			"provider":           cfg.Notification.Provider,
			"supported_providers": []string{"webhook", "slack", "discord", "teams"},
			"webhook_url":        webhookURLDisplay,
			"webhook_secret_set": secretDisplay,
			"timeout_seconds":    cfg.Notification.TimeoutSeconds,
			"max_retries":        cfg.Notification.MaxRetries,
			"min_severity":       cfg.Notification.MinSeverity,
			"notify_lifecycle":   cfg.Notification.NotifyOnLifecycle,
			"notify_deltas":      cfg.Notification.NotifyOnDeltas,
			"concurrency":        cfg.Notification.Concurrency,
			"require_signing":    cfg.Notification.RequireSigning,
			"previous_secret_set": cfg.Notification.WebhookPreviousSecret != "",
			"stats":              stats,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data)
		return 0
	}

	fmt.Println("=== Felix Notification Subsystem ===")
	statusStr := "DISABLED"
	if cfg.Notification.Enabled {
		statusStr = "ENABLED"
	}
	fmt.Printf("State:             %s\n", statusStr)
	fmt.Printf("Provider:          %s\n", cfg.Notification.Provider)
	fmt.Println("Supported:         webhook, slack, discord, teams")
	if auth.IsAdmin() {
		fmt.Printf("Webhook URL:       %s\n", notify.SafeWebhookURL(cfg.Notification.WebhookURL))
	} else {
		fmt.Printf("Webhook URL:       %s\n", "[REDACTED - ADMIN ONLY]")
	}
	secretStr := "None"
	if cfg.Notification.WebhookSecret != "" {
		secretStr = "[CONFIGURED]"
	}
	fmt.Printf("Webhook Secret:    %s\n", secretStr)
	fmt.Printf("Require Signing:   %t\n", cfg.Notification.RequireSigning)
	prevSecretStr := "None"
	if cfg.Notification.WebhookPreviousSecret != "" {
		prevSecretStr = "[CONFIGURED]"
	}
	fmt.Printf("Previous Secret:   %s\n", prevSecretStr)
	fmt.Printf("Timeout:           %ds\n", cfg.Notification.TimeoutSeconds)
	fmt.Printf("Max Retries:       %d\n", cfg.Notification.MaxRetries)
	fmt.Printf("Min Severity:      %s\n", cfg.Notification.MinSeverity)
	fmt.Printf("Lifecycle Events:  %s\n", strings.Join(cfg.Notification.NotifyOnLifecycle, ", "))
	fmt.Printf("Delta Events:      %s\n", strings.Join(cfg.Notification.NotifyOnDeltas, ", "))
	fmt.Printf("Concurrency:       %d\n", cfg.Notification.Concurrency)

	if stats != nil {
		fmt.Println("\n=== Outbox Metrics ===")
		fmt.Printf("Total Records:     %d\n", stats.TotalNotifications)
		fmt.Printf("Pending:           %d\n", stats.PendingCount)
		fmt.Printf("Delivered:         %d\n", stats.DeliveredCount)
		fmt.Printf("Failed:            %d\n", stats.FailedCount)
		healthStr := "HEALTHY"
		if !stats.SubsystemHealthy {
			healthStr = "DEGRADED"
		}
		fmt.Printf("Subsystem Health:  %s\n", healthStr)
	}

	return 0
}

func runNotificationList(args []string) int {
	var (
		statusFilter string
		limit        int = 50
		asJSON       bool
		role         string
		clientID     string
		tenantID     string
		accountID    string
		dbPath       string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--status":
			if i+1 < len(args) {
				statusFilter = args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--json":
			asJSON = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--help", "-h", "help":
			fmt.Println("Usage: felix notification list [--status pending|delivered|failed|all] [--limit N] [--tenant <id>] [--json]")
			return 0
		}
	}

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Store initialization error: %v\n", err)
		return 2
	}
	defer store.Close()

	filter := notify.NotificationFilter{
		TenantID:       tenantID,
		DeliveryStatus: statusFilter,
		Limit:          limit,
	}

	list, err := store.ListNotifications(filter, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed listing notifications: %v\n", err)
		return 2
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
		return 0
	}

	if len(list) == 0 {
		fmt.Println("[*] No notifications found in outbox.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEVENT\tSEVERITY\tSTATUS\tATTEMPTS\tCREATED\tTITLE")
	for _, n := range list {
		createdStr := n.CreatedAt.Format("2006-01-02 15:04:05")
		titleSnippet := n.Title
		if len(titleSnippet) > 40 {
			titleSnippet = titleSnippet[:37] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n",
			n.ID, n.EventType, n.Severity, n.DeliveryStatus, n.AttemptCount, n.MaxAttempts, createdStr, titleSnippet)
	}
	w.Flush()
	return 0
}

func runNotificationShow(args []string) int {
	var notifID string
	var asJSON bool
	var (
		role      string
		clientID  string
		tenantID  string
		accountID string
		dbPath    string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--help", "-h", "help":
			fmt.Println("Usage: felix notification show <notification-id> [--tenant <id>] [--json]")
			return 0
		default:
			if !strings.HasPrefix(args[i], "-") && notifID == "" {
				notifID = args[i]
			}
		}
	}

	if notifID == "" {
		fmt.Fprintln(os.Stderr, "[-] Missing required notification ID argument")
		return 2
	}

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Store initialization error: %v\n", err)
		return 2
	}
	defer store.Close()

	n, err := store.GetNotification(notifID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Notification %s not found or access denied: %v\n", notifID, err)
		return 2
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(n)
		return 0
	}

	fmt.Printf("Notification ID:     %s\n", n.ID)
	fmt.Printf("Tenant ID:           %s\n", n.TenantID)
	if n.AssessmentID != "" {
		fmt.Printf("Assessment ID:       %s\n", n.AssessmentID)
	}
	if n.ExecutionID != "" {
		fmt.Printf("Execution ID:        %s\n", n.ExecutionID)
	}
	fmt.Printf("Event Type:          %s\n", n.EventType)
	fmt.Printf("Severity:            %s\n", n.Severity)
	fmt.Printf("Delivery Status:     %s\n", n.DeliveryStatus)
	fmt.Printf("Attempts:            %d / %d\n", n.AttemptCount, n.MaxAttempts)
	fmt.Printf("Deduplication Key:   %s\n", n.DedupKey)
	fmt.Printf("Title:               %s\n", n.Title)
	fmt.Printf("Message:             %s\n", n.Message)
	if len(n.FindingIDs) > 0 {
		fmt.Printf("Finding IDs:         %s\n", strings.Join(n.FindingIDs, ", "))
	}
	if n.NextRetryAt != nil {
		fmt.Printf("Next Retry At:       %s\n", n.NextRetryAt.Format(time.RFC3339))
	}
	if n.LastError != "" {
		fmt.Printf("Last Error:          %s\n", n.LastError)
	}
	fmt.Printf("Created At:          %s\n", n.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated At:          %s\n", n.UpdatedAt.Format(time.RFC3339))

	return 0
}

func runNotificationRetry(args []string) int {
	var notifID string
	var (
		role      string
		clientID  string
		tenantID  string
		accountID string
		dbPath    string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--help", "-h", "help":
			fmt.Println("Usage: felix notification retry <notification-id> [--tenant <id>]")
			return 0
		default:
			if !strings.HasPrefix(args[i], "-") && notifID == "" {
				notifID = args[i]
			}
		}
	}

	if notifID == "" {
		fmt.Fprintln(os.Stderr, "[-] Missing required notification ID argument")
		return 2
	}

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Store initialization error: %v\n", err)
		return 2
	}
	defer store.Close()

	if err := store.RetryNotification(notifID, auth); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed retrying notification: %v\n", err)
		return 2
	}

	fmt.Printf("[✓] Notification %s reset to PENDING and queued for immediate delivery.\n", notifID)
	return 0
}

func runNotificationTest(args []string) int {
	var (
		overrideURL      string
		overrideProvider   string
		overrideSecret     string
		overridePrevSecret string
		requireSigning     bool
		allowInsecure      bool
		allowLoopback    bool
		asJSON           bool
		role             string
		clientID         string
		tenantID         string
		accountID        string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--url" {
			if i+1 < len(args) {
				overrideURL = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--url=") {
			overrideURL = strings.TrimPrefix(arg, "--url=")
			continue
		}
		if arg == "--provider" {
			if i+1 < len(args) {
				overrideProvider = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--provider=") {
			overrideProvider = strings.TrimPrefix(arg, "--provider=")
			continue
		}
		if arg == "--secret" {
			if i+1 < len(args) {
				overrideSecret = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--secret=") {
			overrideSecret = strings.TrimPrefix(arg, "--secret=")
			continue
		}
		if arg == "--previous-secret" || arg == "--notify-previous-secret" {
			if i+1 < len(args) {
				overridePrevSecret = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--previous-secret=") {
			overridePrevSecret = strings.TrimPrefix(arg, "--previous-secret=")
			continue
		}
		if strings.HasPrefix(arg, "--notify-previous-secret=") {
			overridePrevSecret = strings.TrimPrefix(arg, "--notify-previous-secret=")
			continue
		}
		if arg == "--require-signing" || arg == "--notify-require-signing" {
			requireSigning = true
			continue
		}
		if arg == "--role" {
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--role=") {
			role = strings.TrimPrefix(arg, "--role=")
			continue
		}
		if arg == "--client" {
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--client=") {
			clientID = strings.TrimPrefix(arg, "--client=")
			continue
		}
		if arg == "--tenant" {
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--tenant=") {
			tenantID = strings.TrimPrefix(arg, "--tenant=")
			continue
		}
		if arg == "--account" {
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--account=") {
			accountID = strings.TrimPrefix(arg, "--account=")
			continue
		}
		if arg == "--json" {
			asJSON = true
			continue
		}
		if arg == "--insecure" {
			allowInsecure = true
			continue
		}
		if arg == "--allow-loopback" {
			allowLoopback = true
			continue
		}
		if arg == "--help" || arg == "-h" || arg == "help" {
			fmt.Println("Usage: felix notification test [--url <endpoint>] [--provider <type>] [--json]")
			return 0
		}
	}

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}
	if !auth.IsAdmin() {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: notification test ping requires administrative privileges\n")
		return 2
	}

	cfg, _ := config.LoadWithEnv("")
	targetURL := cfg.Notification.WebhookURL
	if overrideURL != "" {
		targetURL = overrideURL
	}

	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "[-] No webhook URL configured. Specify --url <https://...> or set webhook_url in config.")
		return 2
	}

	providerType := cfg.Notification.Provider
	if overrideProvider != "" {
		providerType = overrideProvider
	}
	if providerType == "" {
		providerType = "webhook"
	}
	secret := resolveNotifySecret(overrideSecret, cfg.Notification.WebhookSecret)
	prevSecret := resolvePreviousSecret(overridePrevSecret, cfg.Notification.WebhookPreviousSecret)
	signingRequired := requireSigning || cfg.Notification.RequireSigning

	insecureAllowed := cfg.Notification.AllowInsecureHTTP || allowInsecure
	loopbackAllowed := cfg.Notification.AllowLoopback || allowLoopback
	if strings.HasPrefix(targetURL, "http://127.0.0.1") || strings.HasPrefix(targetURL, "http://localhost") {
		insecureAllowed = true
		loopbackAllowed = true
	}

	webhookCfg := notify.WebhookConfig{
		URL:               targetURL,
		Secret:            secret,
		PreviousSecret:    prevSecret,
		RequireSigning:    signingRequired,
		Timeout:           time.Duration(cfg.Notification.TimeoutSeconds) * time.Second,
		AllowInsecureHTTP: insecureAllowed,
		AllowPrivateIPs:   cfg.Notification.AllowPrivateIPs,
		AllowLoopback:     loopbackAllowed,
	}

	provider, err := notify.NewProvider(webhookCfg, providerType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Notification provider configuration failed: %v\n", err)
		return 2
	}

	now := time.Now().UTC()
	testNotif := notify.BuildTestNotification("test-tenant", targetURL, now)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Notification.TimeoutSeconds)*time.Second)
	defer cancel()

	receipt, err := provider.Send(ctx, testNotif)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Test notification delivery failed: %v\n", secrets.RedactText(err.Error()))
		return 2
	}

	if asJSON {
		res := map[string]interface{}{
			"success":      true,
			"receipt_id":   receipt.ReceiptID,
			"status_code":  receipt.StatusCode,
			"delivered_at": receipt.DeliveredAt,
			"target_url":   notify.SafeWebhookURL(targetURL),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}

	fmt.Println("[✓] Test notification delivered successfully!")
	fmt.Printf("Receipt ID:    %s\n", receipt.ReceiptID)
	fmt.Printf("HTTP Status:   %d\n", receipt.StatusCode)
	fmt.Printf("Delivered At:  %s\n", receipt.DeliveredAt.Format(time.RFC3339))
	fmt.Printf("Destination:   %s\n", notify.SafeWebhookURL(targetURL))
	return 0
}

func runNotificationDispatch(args []string) int {
	var (
		limit     int = 50
		asJSON    bool
		dbPath    string
		role      string
		clientID  string
		tenantID  string
		accountID string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--limit":
			if i+1 < len(args) {
				limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--json":
			asJSON = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--help", "-h", "help":
			fmt.Println("Usage: felix notification dispatch [--limit N] [--json]")
			return 0
		}
	}

	auth, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}
	if !auth.IsAdmin() {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: notification dispatch requires administrative privileges\n")
		return 2
	}

	cfg, _ := config.LoadWithEnv("")
	if !cfg.Notification.Enabled || cfg.Notification.WebhookURL == "" {
		fmt.Fprintln(os.Stderr, "[-] Notifications are not enabled or webhook URL is not configured.")
		return 2
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Store initialization error: %v\n", err)
		return 2
	}
	defer store.Close()

	webhookCfg := notify.WebhookConfig{
		URL:               cfg.Notification.WebhookURL,
		Secret:            cfg.Notification.WebhookSecret,
		PreviousSecret:    cfg.Notification.WebhookPreviousSecret,
		RequireSigning:    cfg.Notification.RequireSigning,
		Timeout:           time.Duration(cfg.Notification.TimeoutSeconds) * time.Second,
		AllowInsecureHTTP: cfg.Notification.AllowInsecureHTTP,
		AllowPrivateIPs:   cfg.Notification.AllowPrivateIPs,
		AllowLoopback:     cfg.Notification.AllowLoopback,
	}

	provider, err := notify.NewProvider(webhookCfg, cfg.Notification.Provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Provider configuration error: %v\n", err)
		return 2
	}

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{
		Concurrency: cfg.Notification.Concurrency,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Notification.TimeoutSeconds*3)*time.Second)
	defer cancel()

	delivered, err := dispatcher.DispatchBatch(ctx, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dispatch error: %v\n", err)
		return 2
	}

	if asJSON {
		res := map[string]interface{}{
			"delivered_count": delivered,
		}
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return 0
	}

	fmt.Printf("[✓] Dispatched %d notification(s) successfully.\n", delivered)
	return 0
}
