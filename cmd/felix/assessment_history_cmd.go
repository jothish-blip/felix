package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"felix/pkg/assessment"
)

func runAssessmentHistory(args []string) int {
	if len(args) == 0 {
		return runHistoryList(args)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		return runHistoryList(subArgs)
	case "show", "get":
		return runHistoryShow(subArgs)
	case "diff", "compare":
		return runAssessmentDiff(subArgs)
	case "--help", "-h", "help":
		printHistoryHelp()
		return 0
	default:
		// If first argument does not start with '-', treat as 'show <execution-id>'
		if len(args[0]) > 0 && args[0][0] != '-' {
			return runHistoryShow(args)
		}
		// Otherwise treat flags as list flags
		return runHistoryList(args)
	}
}

func printHistoryHelp() {
	fmt.Println("Usage: felix assessment history <subcommand> [flags]")
	fmt.Println("       felix history <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  list              List assessment execution history records (default)")
	fmt.Println("  show <exec-id>    Display comprehensive details of an execution record")
	fmt.Println("  diff <b-id> <c-id> Compare two execution history records to identify finding deltas")
	fmt.Println("\nList Flags:")
	fmt.Println("  --assessment <ref>   Filter by assessment ID or reference")
	fmt.Println("  --schedule <id>      Filter by originating schedule ID")
	fmt.Println("  --status <status>    Filter by execution status (RUNNING, COMPLETED, FAILED, SKIPPED, CANCELLED)")
	fmt.Println("  --source <source>    Filter by initiation source (manual, scheduled, api)")
	fmt.Println("  --since <time>       Filter executions started after timestamp (RFC3339 or duration, e.g. 24h)")
	fmt.Println("  --until <time>       Filter executions started before timestamp (RFC3339)")
	fmt.Println("  --client <id>        Filter by client ID")
	fmt.Println("  --tenant <id>        Filter by tenant ID")
	fmt.Println("  --account <id>       Filter by account ID")
	fmt.Println("  --limit <n>          Maximum records to return (default: 50)")
	fmt.Println("  --offset <n>         Pagination offset")
	fmt.Println("  --json               Output result as JSON")
	fmt.Println("  --db <path>          Path to SQLite database")
	fmt.Println("\nRun 'felix assessment history <subcommand> --help' for details on a specific subcommand.")
}

func runHistoryList(args []string) int {
	var (
		asmRef     string
		schedID    string
		statusStr  string
		source     string
		sinceStr   string
		untilStr   string
		clientID   string
		tenantID   string
		accountID  string
		role       string = "admin"
		limit      int    = 50
		offset     int    = 0
		dbPath     string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--assessment", "--asm":
			if i+1 < len(args) {
				asmRef = args[i+1]
				i++
			}
		case "--schedule", "--sched":
			if i+1 < len(args) {
				schedID = args[i+1]
				i++
			}
		case "--status":
			if i+1 < len(args) {
				statusStr = args[i+1]
				i++
			}
		case "--source":
			if i+1 < len(args) {
				source = args[i+1]
				i++
			}
		case "--since", "--from":
			if i+1 < len(args) {
				sinceStr = args[i+1]
				i++
			}
		case "--until", "--to":
			if i+1 < len(args) {
				untilStr = args[i+1]
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
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--offset":
			if i+1 < len(args) {
				offset, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printHistoryHelp()
			return 0
		}
	}

	store, err := openStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database: %v\n", err)
		return 2
	}
	defer store.Close()

	authCtx, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	var sinceTime *time.Time
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			sinceTime = &t
		} else if dur, err := time.ParseDuration(sinceStr); err == nil {
			t := time.Now().UTC().Add(-dur)
			sinceTime = &t
		} else {
			fmt.Fprintf(os.Stderr, "[-] Invalid --since format %q (expected RFC3339 or duration e.g. 24h)\n", sinceStr)
			return 2
		}
	}

	var untilTime *time.Time
	if untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			untilTime = &t
		} else {
			fmt.Fprintf(os.Stderr, "[-] Invalid --until format %q (expected RFC3339)\n", untilStr)
			return 1
		}
	}

	opts := assessment.ExecutionListOptions{
		Auth:             authCtx,
		AssessmentID:     asmRef,
		ScheduleID:       schedID,
		ClientID:         clientID,
		TenantID:         tenantID,
		AccountID:        accountID,
		Status:           assessment.AssessmentStatus(statusStr),
		InitiationSource: source,
		Since:            sinceTime,
		Until:            untilTime,
		Limit:            limit,
		Offset:           offset,
	}

	records, total, err := store.ListExecutionHistory(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed listing execution history: %v\n", err)
		return 1
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]any{
			"total":      total,
			"executions": records,
		}, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(records) == 0 {
		fmt.Println("No assessment execution history records found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "EXECUTION ID\tASSESSMENT\tSOURCE\tSTATUS\tSTARTED AT\tDURATION\tFINDINGS\tTARGETS\n")
	for _, r := range records {
		durStr := "-"
		if r.DurationMs > 0 {
			durStr = (time.Duration(r.DurationMs) * time.Millisecond).Round(time.Millisecond).String()
		}
		startedStr := r.StartedAt.Format("2006-01-02 15:04:05")
		srcStr := r.InitiationSource
		if r.ScheduleID != "" {
			srcStr = "scheduled"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			r.ID, r.AssessmentID, srcStr, r.Status, startedStr, durStr, r.FindingCount, r.TargetCount,
		)
	}
	w.Flush()
	return 0
}

func runHistoryShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Error: execution ID is required")
		return 2
	}

	id := args[0]
	var (
		role       string = "admin"
		clientID   string
		tenantID   string
		accountID  string
		dbPath     string
		jsonOutput bool
	)

	for i := 1; i < len(args); i++ {
		switch args[i] {
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
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		}
	}

	store, err := openStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database: %v\n", err)
		return 2
	}
	defer store.Close()

	authCtx, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	exec, err := store.GetExecutionHistory(id, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution record %q not found or access denied: %v\n", id, err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(exec, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	fmt.Println("================================================================================")
	fmt.Printf("ASSESSMENT EXECUTION RECORD: %s\n", exec.ID)
	fmt.Println("================================================================================")
	fmt.Printf("Assessment ID:    %s\n", exec.AssessmentID)
	if exec.ScheduleID != "" {
		fmt.Printf("Origin Schedule:  %s\n", exec.ScheduleID)
		if exec.ScheduledFor != nil {
			fmt.Printf("Scheduled For:    %s\n", exec.ScheduledFor.Format(time.RFC3339))
		}
	}
	fmt.Printf("Initiation Source:%s\n", exec.InitiationSource)
	if exec.ClientID != "" {
		fmt.Printf("Client / Tenant:  %s / %s\n", exec.ClientID, exec.TenantID)
	}
	if exec.AssessmentType != "" {
		fmt.Printf("Assessment Type:  %s\n", exec.AssessmentType)
	}
	fmt.Printf("Status:           %s\n", exec.Status)
	fmt.Printf("Started At:       %s\n", exec.StartedAt.Format(time.RFC3339))
	if exec.CompletedAt != nil {
		fmt.Printf("Completed At:     %s\n", exec.CompletedAt.Format(time.RFC3339))
	}
	if exec.DurationMs > 0 {
		dur := (time.Duration(exec.DurationMs) * time.Millisecond).Round(time.Millisecond)
		fmt.Printf("Duration:         %s\n", dur)
	}
	fmt.Printf("Targets Run:      %d\n", exec.TargetCount)
	fmt.Printf("Findings Count:   %d\n", exec.FindingCount)
	fmt.Printf("Requests Sent:    %d\n", exec.RequestCount)
	if exec.SnapshotID != "" {
		fmt.Printf("Snapshot ID:      %s\n", exec.SnapshotID)
	}
	if exec.ErrorMessage != "" {
		fmt.Printf("Error / Refusal:  %s\n", exec.ErrorMessage)
	}
	return 0
}
