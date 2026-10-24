package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/clierror"
	"felix/pkg/crawler"
	"felix/pkg/monitor"
)

// runMonitor routes subcommands for "felix monitor".
func runMonitor(args []string) int {
	if len(args) == 0 {
		printMonitorHelp()
		return clierror.ExitSuccess
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "snapshot":
		return runMonitorSnapshot(subArgs)
	case "diff", "check":
		return runMonitorDiff(subArgs)
	case "status":
		return runMonitorStatus(subArgs)
	case "baseline":
		return runMonitorBaseline(subArgs)
	case "test-webhook":
		return runMonitorTestWebhook(subArgs)
	case "help", "--help", "-h":
		printMonitorHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown monitor subcommand: %s\n\n", subCmd)
		printMonitorHelp()
		return clierror.ExitOperational
	}
}

type monitorCommonFlags struct {
	profilePath string
	stateDir    string
	jsonOutput  bool
	quiet       bool
}

func parseMonitorFlags(args []string) (monitorCommonFlags, map[string]string, error) {
	flags := monitorCommonFlags{}
	extra := make(map[string]string)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			extra["help"] = "true"
			return flags, extra, nil
		}
		if arg == "--profile" || arg == "-p" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return flags, extra, fmt.Errorf("%s requires a file path argument", arg)
			}
			i++
			flags.profilePath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			flags.profilePath = strings.TrimPrefix(arg, "--profile=")
			continue
		}
		if arg == "--state-dir" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return flags, extra, fmt.Errorf("%s requires a directory argument", arg)
			}
			i++
			flags.stateDir = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--state-dir=") {
			flags.stateDir = strings.TrimPrefix(arg, "--state-dir=")
			continue
		}
		if arg == "--json" {
			flags.jsonOutput = true
			continue
		}
		if arg == "--quiet" || arg == "-q" {
			flags.quiet = true
			continue
		}
		if arg == "--notify" {
			extra["notify"] = "true"
			continue
		}
		if arg == "--reset" {
			extra["reset"] = "true"
			continue
		}
		if arg == "--provider" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				extra["provider"] = args[i]
			}
			continue
		}
		if strings.HasPrefix(arg, "--provider=") {
			extra["provider"] = strings.TrimPrefix(arg, "--provider=")
			continue
		}
		if arg == "--reason" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				extra["reason"] = args[i]
			}
			continue
		}
		if strings.HasPrefix(arg, "--reason=") {
			extra["reason"] = strings.TrimPrefix(arg, "--reason=")
			continue
		}
		// Positional profile path fallback
		if flags.profilePath == "" && !strings.HasPrefix(arg, "-") {
			flags.profilePath = arg
		}
	}

	return flags, extra, nil
}

func loadProfileAndEngine(flags monitorCommonFlags) (*api.TargetProfile, *monitor.MonitorEngine, int) {
	if flags.profilePath == "" {
		fmt.Fprintf(os.Stderr, "[-] error: missing target profile file path (--profile felix.target.yml)\n")
		return nil, nil, clierror.ExitOperational
	}

	prof, err := api.LoadTargetProfile(flags.profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to load target profile %s: %v\n", flags.profilePath, err)
		return nil, nil, clierror.ExitOperational
	}

	engine, err := monitor.NewMonitorEngine(prof, flags.stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize monitor engine: %v\n", err)
		return nil, nil, clierror.ExitOperational
	}

	return prof, engine, clierror.ExitSuccess
}

func getTargetIdentifier(prof *api.TargetProfile) string {
	if prof != nil {
		if prof.Target.Name != "" {
			return prof.Target.Name
		}
		if len(prof.Target.BaseURLs) > 0 {
			return prof.Target.BaseURLs[0]
		}
	}
	return "default_target"
}

// runMonitorSnapshot captures a new API surface snapshot.
func runMonitorSnapshot(args []string) int {
	flags, extra, err := parseMonitorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
		return clierror.ExitOperational
	}
	if extra["help"] == "true" {
		printMonitorSnapshotHelp()
		return clierror.ExitSuccess
	}

	prof, engine, exitCode := loadProfileAndEngine(flags)
	if exitCode != clierror.ExitSuccess {
		return exitCode
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	targetID := getTargetIdentifier(prof)

	// Harvest route candidates declared in profile or target comparisons
	var candidates []crawler.RouteCandidate
	for _, comp := range prof.CrossTenantTests.Comparisons {
		rPath := comp.Path
		if rPath == "" {
			rPath = "/api/v1/resources/" + comp.ResourceID
		}
		method := comp.Method
		if method == "" {
			method = "GET"
		}
		candidates = append(candidates, crawler.RouteCandidate{
			ID:               fmt.Sprintf("cand_%s", comp.ResourceID),
			Path:             rPath,
			HTTPMethod:       method,
			OriginatingAsset: "felix.target.yml",
			SourceType:       crawler.SourceTypeNextManifest,
			Confidence:       crawler.ConfidenceConfirmed,
			DiscoveredAt:     time.Now().UTC(),
		})
	}

	// For base URLs, include standard default route anchors
	for _, bURL := range prof.Target.BaseURLs {
		candidates = append(candidates, crawler.RouteCandidate{
			ID:               "root_anchor",
			Path:             "/api",
			HTTPMethod:       "GET",
			OriginatingAsset: bURL,
			SourceType:       crawler.SourceTypeNextManifest,
			Confidence:       crawler.ConfidenceConfirmed,
			DiscoveredAt:     time.Now().UTC(),
		})
	}

	opts := monitor.SnapshotBuildOptions{
		TargetID:   targetID,
		TargetName: prof.Target.Name,
		BaseURLs:   prof.Target.BaseURLs,
		IsComplete: true,
	}

	snap, err := engine.CaptureSnapshot(ctx, candidates, nil, nil, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to capture snapshot: %v\n", err)
		return clierror.ExitOperational
	}

	if flags.jsonOutput {
		data, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Println(string(data))
		return clierror.ExitSuccess
	}

	if !flags.quiet {
		fmt.Println("[+] Successfully captured API surface snapshot")
		fmt.Printf("    Snapshot ID:   %s\n", snap.ID)
		fmt.Printf("    Target ID:     %s\n", snap.TargetID)
		fmt.Printf("    Captured At:   %s\n", snap.CollectedAt.Format(time.RFC3339))
		fmt.Printf("    Routes Count:  %d\n", len(snap.Routes))
		fmt.Printf("    Complete:      %t\n", snap.IsComplete)
		if len(snap.Routes) > 0 {
			fmt.Println("\n    Sample Routes:")
			limit := 5
			if len(snap.Routes) < limit {
				limit = len(snap.Routes)
			}
			for i := 0; i < limit; i++ {
				r := snap.Routes[i]
				fmt.Printf("      • [%-6s] %s (doc: %s)\n", strings.Join(r.Methods, ","), r.CanonicalPath, r.DocumentationStatus)
			}
		}
	}

	return clierror.ExitSuccess
}

// runMonitorDiff compares the latest snapshot against baseline and optionally alerts.
func runMonitorDiff(args []string) int {
	flags, extra, err := parseMonitorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
		return clierror.ExitOperational
	}
	if extra["help"] == "true" {
		printMonitorDiffHelp()
		return clierror.ExitSuccess
	}

	prof, engine, exitCode := loadProfileAndEngine(flags)
	if exitCode != clierror.ExitSuccess {
		return exitCode
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	targetID := getTargetIdentifier(prof)

	// Retrieve latest snapshot, or capture if none exists yet
	latestSnap, err := engine.CaptureSnapshot(ctx, nil, nil, nil, monitor.SnapshotBuildOptions{
		TargetID:   targetID,
		TargetName: prof.Target.Name,
		BaseURLs:   prof.Target.BaseURLs,
		IsComplete: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve snapshot for comparison: %v\n", err)
		return clierror.ExitOperational
	}

	sendAlerts := extra["notify"] == "true"
	report, delivery, err := engine.RunDiff(ctx, latestSnap, sendAlerts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Temporal drift comparison failed: %v\n", err)
		return clierror.ExitOperational
	}

	if flags.jsonOutput {
		out := map[string]interface{}{
			"drift_report": report,
		}
		if delivery != nil {
			out["delivery_summary"] = delivery
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return clierror.ExitSuccess
	}

	if !flags.quiet {
		fmt.Println("================================================================================")
		fmt.Println("API Surface Temporal Drift Report (P14.5)")
		fmt.Println("================================================================================")
		fmt.Printf("  Target ID:        %s\n", report.TargetID)
		fmt.Printf("  Baseline ID:      %s\n", report.BaselineSnapshotID)
		fmt.Printf("  Current ID:       %s\n", report.CurrentSnapshotID)
		fmt.Printf("  Total Changes:    %d\n", report.TotalEvents)
		if len(report.Summary) > 0 {
			fmt.Println("\n  Change Breakdown:")
			for class, count := range report.Summary {
				fmt.Printf("    • %-32s %d\n", class, count)
			}
		}

		if len(report.Events) > 0 {
			fmt.Println("\n  Detected Drift Events:")
			for _, evt := range report.Events {
				sens := ""
				if len(evt.SensitiveIdentifiers) > 0 {
					sens = fmt.Sprintf(" [%s]", strings.Join(evt.SensitiveIdentifiers, ", "))
				}
				fmt.Printf("    [%-8s] %-30s %s%s\n", evt.Priority, evt.Classification, evt.CanonicalRoute, sens)
				fmt.Printf("               Rationale: %s\n", evt.PriorityRationale)
				if evt.SuggestedAction != "" {
					fmt.Printf("               Action:    %s\n", evt.SuggestedAction)
				}
			}
		}

		if delivery != nil {
			fmt.Println("\n  Webhook Delivery Summary:")
			fmt.Printf("    Attempted:      %d\n", delivery.TotalAttempted)
			fmt.Printf("    Delivered:      %d\n", delivery.TotalDelivered)
			fmt.Printf("    Skipped (Dedupe): %d\n", delivery.TotalSkippedDedupe)
			fmt.Printf("    Failed:         %d\n", delivery.TotalFailed)
		}
		fmt.Println("================================================================================")
	}

	return clierror.ExitSuccess
}

// runMonitorStatus displays baseline, latest snapshot, and delivery health.
func runMonitorStatus(args []string) int {
	flags, extra, err := parseMonitorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
		return clierror.ExitOperational
	}
	if extra["help"] == "true" {
		printMonitorStatusHelp()
		return clierror.ExitSuccess
	}

	prof, engine, exitCode := loadProfileAndEngine(flags)
	if exitCode != clierror.ExitSuccess {
		return exitCode
	}

	ctx := context.Background()
	targetID := getTargetIdentifier(prof)

	status, err := engine.GetStatus(ctx, targetID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to retrieve monitor status: %v\n", err)
		return clierror.ExitOperational
	}

	if flags.jsonOutput {
		data, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(data))
		return clierror.ExitSuccess
	}

	fmt.Println("================================================================================")
	fmt.Println("API Surface Monitor Status (P14.5)")
	fmt.Println("================================================================================")
	fmt.Printf("  Target ID:            %s\n", status.TargetID)
	fmt.Printf("  State Directory:      %s\n", status.StateDirectory)
	fmt.Printf("  Monitoring Enabled:   %t\n", status.MonitoringOn)
	fmt.Printf("  Configured Webhooks:  %d\n", status.ConfiguredHooks)
	fmt.Printf("  Has Active Baseline:  %t\n", status.HasBaseline)
	if status.HasBaseline {
		fmt.Printf("    Baseline ID:        %s\n", status.BaselineID)
		if status.BaselineDate != nil {
			fmt.Printf("    Baseline Date:      %s\n", status.BaselineDate.Format(time.RFC3339))
		}
		fmt.Printf("    Baseline Routes:    %d\n", status.BaselineRoutes)
	}
	fmt.Printf("  Total Snapshots:      %d\n", status.TotalSnapshots)
	if status.LatestSnapshotID != "" {
		fmt.Printf("    Latest Snapshot ID: %s\n", status.LatestSnapshotID)
		if status.LatestScanDate != nil {
			fmt.Printf("    Latest Scan Date:   %s\n", status.LatestScanDate.Format(time.RFC3339))
		}
		fmt.Printf("    Latest Routes:      %d\n", status.LatestRoutes)
	}
	fmt.Printf("  Active Drift Events:  %d\n", status.ActiveDriftCount)
	fmt.Printf("  Delivered Alerts:     %d\n", status.TotalDelivered)
	fmt.Println("================================================================================")

	return clierror.ExitSuccess
}

// runMonitorBaseline inspects or resets the active baseline.
func runMonitorBaseline(args []string) int {
	flags, extra, err := parseMonitorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
		return clierror.ExitOperational
	}
	if extra["help"] == "true" {
		printMonitorBaselineHelp()
		return clierror.ExitSuccess
	}

	prof, engine, exitCode := loadProfileAndEngine(flags)
	if exitCode != clierror.ExitSuccess {
		return exitCode
	}

	ctx := context.Background()
	targetID := getTargetIdentifier(prof)

	if extra["reset"] == "true" {
		reason := extra["reason"]
		if reason == "" {
			reason = "Operator manual baseline reset via CLI"
		}
		if err := engine.ResetBaseline(ctx, targetID, nil, reason); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to reset baseline: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Successfully reset baseline for target %q (Reason: %s)\n", targetID, reason)
		return clierror.ExitSuccess
	}

	// Read current baseline
	status, err := engine.GetStatus(ctx, targetID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read baseline status: %v\n", err)
		return clierror.ExitOperational
	}

	if !status.HasBaseline {
		fmt.Printf("[-] No active baseline found for target %q. Run 'felix monitor snapshot --profile <file>' to initialize.\n", targetID)
		return clierror.ExitOperational
	}

	fmt.Printf("[+] Active Baseline for target %q:\n", targetID)
	fmt.Printf("    Snapshot ID:  %s\n", status.BaselineID)
	if status.BaselineDate != nil {
		fmt.Printf("    Established:  %s\n", status.BaselineDate.Format(time.RFC3339))
	}
	fmt.Printf("    Routes Count: %d\n", status.BaselineRoutes)
	fmt.Println("\nTo establish a new baseline from the latest scan, run:")
	fmt.Printf("  felix monitor baseline --profile %s --reset\n", flags.profilePath)

	return clierror.ExitSuccess
}

// runMonitorTestWebhook transmits a synthetic verification alert to a configured webhook.
func runMonitorTestWebhook(args []string) int {
	flags, extra, err := parseMonitorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
		return clierror.ExitOperational
	}
	if extra["help"] == "true" {
		printMonitorTestWebhookHelp()
		return clierror.ExitSuccess
	}

	_, engine, exitCode := loadProfileAndEngine(flags)
	if exitCode != clierror.ExitSuccess {
		return exitCode
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	provider := extra["provider"]
	receipt, err := engine.TestWebhook(ctx, "", provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Webhook test failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Printf("[+] Synthetic test webhook successfully delivered\n")
	fmt.Printf("    Receipt ID:  %s\n", receipt.ReceiptID)
	fmt.Printf("    Provider:    %s\n", receipt.ProviderName)
	fmt.Printf("    Status Code: %d\n", receipt.StatusCode)
	fmt.Printf("    Delivered:   %s\n", receipt.DeliveredAt.Format(time.RFC3339))

	return clierror.ExitSuccess
}

func printMonitorHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix monitor <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  snapshot      Capture and persist an API surface snapshot")
	fmt.Println("  diff          Compare surface against baseline and detect temporal drift")
	fmt.Println("  status        Display baseline state, history, and delivery health")
	fmt.Println("  baseline      Inspect or reset the authoritative baseline snapshot")
	fmt.Println("  test-webhook  Send a synthetic verification alert to a configured webhook")
	fmt.Println("\nFlags:")
	fmt.Println("  --profile, -p   Path to target profile (felix.target.yml)")
	fmt.Println("  --state-dir     Override state directory (default: ./felix-state)")
	fmt.Println("  --json          Output structured JSON")
	fmt.Println("  --quiet, -q     Suppress informational output")
	fmt.Println("  --help, -h      Show command help")
}

func printMonitorSnapshotHelp() {
	fmt.Println("Usage: felix monitor snapshot --profile felix.target.yml [flags]")
}

func printMonitorDiffHelp() {
	fmt.Println("Usage: felix monitor diff --profile felix.target.yml [--notify] [flags]")
}

func printMonitorStatusHelp() {
	fmt.Println("Usage: felix monitor status --profile felix.target.yml [flags]")
}

func printMonitorBaselineHelp() {
	fmt.Println("Usage: felix monitor baseline --profile felix.target.yml [--reset] [--reason <text>]")
}

func printMonitorTestWebhookHelp() {
	fmt.Println("Usage: felix monitor test-webhook --profile felix.target.yml [--provider slack|discord|teams]")
}
