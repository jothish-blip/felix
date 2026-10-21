package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"felix/pkg/assessment"
)

func runAssessmentSchedule(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printScheduleHelp()
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "create", "add":
		return runScheduleCreate(subArgs)
	case "list", "ls":
		return runScheduleList(subArgs)
	case "show", "get":
		return runScheduleShow(subArgs)
	case "enable":
		return runScheduleSetEnabled(subArgs, true)
	case "disable":
		return runScheduleSetEnabled(subArgs, false)
	case "delete", "rm":
		return runScheduleDelete(subArgs)
	case "run-due":
		return runScheduleRunDue(subArgs)
	case "daemon", "start", "worker", "run":
		return runScheduleDaemon(subArgs)
	case "history", "dispatches":
		return runScheduleHistory(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown schedule subcommand: %s\n\n", sub)
		printScheduleHelp()
		return 2
	}
}

func printScheduleHelp() {
	fmt.Println("Usage: felix assessment schedule <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  create     Configure a new scheduled recurring assessment")
	fmt.Println("  list       List configured assessment schedules")
	fmt.Println("  show       Display details of a specific schedule")
	fmt.Println("  enable     Enable a schedule for background execution")
	fmt.Println("  disable    Disable a schedule to pause execution")
	fmt.Println("  delete     Delete an assessment schedule")
	fmt.Println("  run-due    Execute all currently due schedules on demand")
	fmt.Println("  daemon     Run continuous background scheduler daemon (aliases: start, worker)")
	fmt.Println("  history    Display execution dispatch history for a schedule")
	fmt.Println("\nRun 'felix assessment schedule <subcommand> --help' for details on flags.")
}

func resolveAuthFromFlags(role, clientID, tenantID, accountID string) (assessment.TenantAuthContext, error) {
	if role == "" && clientID == "" && tenantID == "" && accountID == "" {
		// Default local CLI operator context to admin
		role = "admin"
	}
	if role != "" && (role == "admin" || role == "system_admin" || role == "operator_admin") {
		return assessment.AuthorizeAdminContext(role)
	}
	if clientID == "" && (tenantID != "" || accountID != "") {
		clientID = "cli-operator"
	}
	return assessment.ResolveAuthContext(role, clientID, tenantID, accountID)
}

func openStore(dbPath string) (*assessment.SQLiteStore, error) {
	return assessment.NewSQLiteStore(dbPath)
}

func runScheduleCreate(args []string) int {
	var (
		name         string
		desc         string
		asmRef       string
		recTypeStr   string
		recExpr      string
		intervalStr  string
		tz           string = "UTC"
		catchUp      string = "once"
		clientID     string
		tenantID     string
		accountID    string
		role         string = "admin"
		dbPath       string
		jsonOutput   bool
		timeoutSec   int
		concurrency  int
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--desc", "--description":
			if i+1 < len(args) {
				desc = args[i+1]
				i++
			}
		case "--assessment", "--asm":
			if i+1 < len(args) {
				asmRef = args[i+1]
				i++
			}
		case "--type":
			if i+1 < len(args) {
				recTypeStr = strings.ToLower(args[i+1])
				i++
			}
		case "--expr":
			if i+1 < len(args) {
				recExpr = args[i+1]
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				intervalStr = args[i+1]
				i++
			}
		case "--timezone", "--tz":
			if i+1 < len(args) {
				tz = args[i+1]
				i++
			}
		case "--catch-up":
			if i+1 < len(args) {
				catchUp = args[i+1]
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
		case "--timeout":
			if i+1 < len(args) {
				timeoutSec, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--concurrency":
			if i+1 < len(args) {
				concurrency, _ = strconv.Atoi(args[i+1])
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
			fmt.Println("Usage: felix assessment schedule create --name <name> --assessment <id|ref> --type <type> --expr <expr> [flags]")
			fmt.Println("\nFlags:")
			fmt.Println("  --name <str>         Schedule name (required)")
			fmt.Println("  --assessment <ref>   Target assessment ID or reference (required)")
			fmt.Println("  --type <type>        Recurrence type: interval, daily, weekly, cron, once (required)")
			fmt.Println("  --expr <expr>        Recurrence expression, e.g. '@every 1h', '02:30', 'Mon 09:00', '0 2 * * *'")
			fmt.Println("  --interval <sec>     Interval duration in seconds or string (e.g. 3600, 1h)")
			fmt.Println("  --timezone <tz>      IANA timezone (default: UTC)")
			fmt.Println("  --catch-up <policy>  Catch-up policy: once (default) or skip")
			fmt.Println("  --json               Output result as JSON")
			return 0
		}
	}

	if name == "" || asmRef == "" || recTypeStr == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --name, --assessment, and --type are required")
		return 2
	}

	var intervalSec int64
	if intervalStr != "" {
		if sec, err := strconv.ParseInt(intervalStr, 10, 64); err == nil {
			intervalSec = sec
		} else if dur, err := time.ParseDuration(intervalStr); err == nil {
			intervalSec = int64(dur.Seconds())
		}
	}

	store, err := openStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database: %v\n", err)
		return 2
	}
	defer store.Close()

	asm, err := store.GetAssessment(asmRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", asmRef, err)
		return 2
	}

	authCtx, err := resolveAuthFromFlags(role, clientID, tenantID, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	sched := &assessment.AssessmentSchedule{
		Name:            name,
		Description:     desc,
		AssessmentID:    asm.ID,
		AssessmentRef:   asm.Ref,
		ClientID:        clientID,
		TenantID:        tenantID,
		AccountID:       accountID,
		RecurrenceType:  assessment.RecurrenceType(recTypeStr),
		RecurrenceExpr:  recExpr,
		IntervalSeconds: intervalSec,
		Timezone:        tz,
		IsEnabled:       true,
		CatchUpPolicy:   catchUp,
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			TimeoutSeconds: timeoutSec,
			Concurrency:    concurrency,
		},
	}

	if err := store.CreateSchedule(sched, authCtx); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create schedule: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(sched, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	fmt.Printf("[+] Schedule created successfully!\n")
	fmt.Printf("    ID:          %s\n", sched.ID)
	fmt.Printf("    Name:        %s\n", sched.Name)
	fmt.Printf("    Assessment:  %s (%s)\n", asm.Name, asm.Ref)
	fmt.Printf("    Recurrence:  %s (%s)\n", sched.RecurrenceType, sched.RecurrenceExpr)
	fmt.Printf("    Timezone:    %s\n", sched.Timezone)
	fmt.Printf("    Next Due:    %s\n", sched.NextDueAt.Format(time.RFC3339))
	return 0
}

func runScheduleList(args []string) int {
	var (
		asmRef     string
		clientID   string
		tenantID   string
		accountID  string
		role       string = "admin"
		enabledStr string
		dbPath     string
		jsonOutput bool
		limit      int = 50
		offset     int = 0
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--assessment", "--asm":
			if i+1 < len(args) {
				asmRef = args[i+1]
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
		case "--enabled":
			if i+1 < len(args) {
				enabledStr = args[i+1]
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

	var isEnabled *bool
	if enabledStr != "" {
		val := enabledStr == "true" || enabledStr == "1"
		isEnabled = &val
	}

	asmID := asmRef
	if asmRef != "" {
		if asm, err := store.GetAssessment(asmRef); err == nil && asm != nil {
			asmID = asm.ID
		}
	}

	opts := assessment.ScheduleListOptions{
		Auth:         authCtx,
		ClientID:     clientID,
		TenantID:     tenantID,
		AccountID:    accountID,
		AssessmentID: asmID,
		IsEnabled:    isEnabled,
		Limit:        limit,
		Offset:       offset,
	}

	schedules, total, err := store.ListSchedules(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to list schedules: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]any{
			"total":     total,
			"schedules": schedules,
		}, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(schedules) == 0 {
		fmt.Println("No assessment schedules found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNAME\tASSESSMENT\tRECURRENCE\tENABLED\tNEXT DUE\tLAST RUN\n")
	for _, s := range schedules {
		en := "YES"
		if !s.IsEnabled {
			en = "NO"
		}
		lastRun := "-"
		if s.LastDispatchedAt != nil {
			lastRun = s.LastDispatchedAt.Format("2006-01-02 15:04")
		}
		rec := fmt.Sprintf("%s (%s)", s.RecurrenceType, s.RecurrenceExpr)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Name, s.AssessmentID, rec, en,
			s.NextDueAt.Format("2006-01-02 15:04"), lastRun,
		)
	}
	w.Flush()
	return 0
}

func runScheduleShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Error: schedule ID is required")
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

	sched, err := store.GetSchedule(id, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Schedule %q not found or access denied: %v\n", id, err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(sched, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	fmt.Println("================================================================================")
	fmt.Printf("SCHEDULE: %s (%s)\n", sched.Name, sched.ID)
	fmt.Println("================================================================================")
	fmt.Printf("Assessment ID:    %s\n", sched.AssessmentID)
	fmt.Printf("Client / Tenant:  %s / %s\n", sched.ClientID, sched.TenantID)
	fmt.Printf("Recurrence:       %s (%s)\n", sched.RecurrenceType, sched.RecurrenceExpr)
	fmt.Printf("Timezone:         %s\n", sched.Timezone)
	fmt.Printf("Catch-up Policy:  %s\n", sched.CatchUpPolicy)
	fmt.Printf("Enabled:          %t\n", sched.IsEnabled)
	fmt.Printf("Next Due:         %s\n", sched.NextDueAt.Format(time.RFC3339))
	if sched.LastDispatchedAt != nil {
		fmt.Printf("Last Dispatched:  %s\n", sched.LastDispatchedAt.Format(time.RFC3339))
	}
	if sched.LastCompletedAt != nil {
		fmt.Printf("Last Completed:   %s\n", sched.LastCompletedAt.Format(time.RFC3339))
	}
	if sched.LastExecutionID != "" {
		fmt.Printf("Last Execution:   %s\n", sched.LastExecutionID)
	}
	fmt.Printf("Dispatch Count:   %d (Failures: %d, Consecutive: %d)\n",
		sched.DispatchCount, sched.FailureCount, sched.ConsecutiveFailures)
	if sched.LastError != "" {
		fmt.Printf("Last Error:       %s\n", sched.LastError)
	}
	return 0
}

func runScheduleSetEnabled(args []string, enable bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Error: schedule ID is required")
		return 2
	}

	id := args[0]
	var (
		role      string = "admin"
		clientID  string
		tenantID  string
		accountID string
		dbPath    string
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

	sched, err := store.GetSchedule(id, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Schedule %q not found or unauthorized: %v\n", id, err)
		return 2
	}

	sched.IsEnabled = enable
	if err := store.UpdateSchedule(sched, authCtx); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed updating schedule state: %v\n", err)
		return 2
	}

	action := "enabled"
	if !enable {
		action = "disabled"
	}
	fmt.Printf("[+] Schedule %s successfully %s.\n", id, action)
	return 0
}

func runScheduleDelete(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Error: schedule ID is required")
		return 2
	}

	id := args[0]
	var (
		role      string = "admin"
		clientID  string
		tenantID  string
		accountID string
		dbPath    string
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

	if err := store.DeleteSchedule(id, authCtx); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed deleting schedule: %v\n", err)
		return 2
	}

	fmt.Printf("[+] Schedule %s deleted.\n", id)
	return 0
}

func runScheduleRunDue(args []string) int {
	var (
		dbPath     string
		jsonOutput bool
		limit      int = 50
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--limit":
			if i+1 < len(args) {
				limit, _ = strconv.Atoi(args[i+1])
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

	controller := assessment.NewController(store)
	cfg := assessment.DefaultSchedulerConfig()
	cfg.ClaimBatchSize = limit
	scheduler := assessment.NewScheduler(store, controller, cfg)

	now := time.Now().UTC()
	dispatched, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error running due schedules: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.Marshal(map[string]any{
			"dispatched": dispatched,
			"timestamp":  now,
		})
		fmt.Println(string(data))
		return 0
	}

	fmt.Printf("[+] Checked and dispatched %d due assessment schedule(s).\n", dispatched)
	return 0
}

func runScheduleHistory(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Error: schedule ID is required")
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

	dispatches, err := store.GetScheduleDispatches(id, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed fetching dispatches: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(dispatches, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(dispatches) == 0 {
		fmt.Println("No execution dispatches recorded for this schedule.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "DISPATCH ID\tSTATUS\tSCHEDULED FOR\tDISPATCHED AT\tEXECUTION ID\tEXEC STATUS\tFINDINGS\tERROR\n")
	for _, d := range dispatches {
		exec := d.ExecutionID
		if exec == "" {
			exec = "-"
		}
		execStatus := "-"
		findings := "-"
		if d.ExecutionID != "" {
			if execRec, err := store.GetExecutionHistory(d.ExecutionID, authCtx); err == nil && execRec != nil {
				execStatus = string(execRec.Status)
				findings = strconv.Itoa(execRec.FindingCount)
			}
		}
		errMsg := d.ErrorMessage
		if errMsg == "" {
			errMsg = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.ID, d.Status,
			d.ScheduledFor.Format("2006-01-02 15:04"),
			d.DispatchedAt.Format("2006-01-02 15:04"),
			exec, execStatus, findings, errMsg,
		)
	}
	w.Flush()
	return 0
}

func runScheduleDaemon(args []string) int {
	var (
		pollIntervalStr string = "10s"
		concurrency     int    = 4
		batchSize       int    = 10
		shutdownTimeout string = "30s"
		dbPath          string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval", "--poll-interval":
			if i+1 < len(args) {
				pollIntervalStr = args[i+1]
				i++
			}
		case "--concurrency":
			if i+1 < len(args) {
				concurrency, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--batch-size":
			if i+1 < len(args) {
				batchSize, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--shutdown-timeout", "--timeout":
			if i+1 < len(args) {
				shutdownTimeout = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment schedule daemon [flags]")
			fmt.Println("\nRun the continuous background scheduler daemon to poll and dispatch due assessments.")
			fmt.Println("\nFlags:")
			fmt.Println("  --interval <dur>         Poll interval between schedule checks (default: 10s)")
			fmt.Println("  --concurrency <int>      Maximum concurrent assessment executions (default: 4)")
			fmt.Println("  --batch-size <int>       Maximum schedules claimed per poll tick (default: 10)")
			fmt.Println("  --shutdown-timeout <dur> Graceful shutdown timeout (default: 30s)")
			fmt.Println("  --db <path>              Path to SQLite database")
			return 0
		}
	}

	pollDur, err := time.ParseDuration(pollIntervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid poll interval %q: %v\n", pollIntervalStr, err)
		return 2
	}

	timeoutDur, err := time.ParseDuration(shutdownTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid shutdown timeout %q: %v\n", shutdownTimeout, err)
		return 2
	}

	store, err := openStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database: %v\n", err)
		return 2
	}
	defer store.Close()

	actualDB := dbPath
	if actualDB == "" {
		actualDB, _ = assessment.DefaultDBPath()
	}

	controller := assessment.NewController(store)
	cfg := assessment.SchedulerConfig{
		PollInterval:    pollDur,
		MaxConcurrency:  concurrency,
		ClaimBatchSize:  batchSize,
		ShutdownTimeout: timeoutDur,
	}

	sched := assessment.NewScheduler(store, controller, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sched.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to start scheduler: %v\n", err)
		return 2
	}

	fmt.Println("===========================================================")
	fmt.Println("  FELIX SCHEDULER :: Continuous Assessment Daemon")
	fmt.Println("  \"Automated Posture Monitoring & Periodic Auditing\"")
	fmt.Println("===========================================================")
	fmt.Printf("[+] Scheduler Daemon Active (PID: %d):\n", os.Getpid())
	fmt.Printf("    • Polling Interval: %v\n", pollDur)
	fmt.Printf("    • Max Concurrency:  %d\n", concurrency)
	fmt.Printf("    • Claim Batch Size: %d\n", batchSize)
	fmt.Printf("    • Database:         %s\n\n", actualDB)
	fmt.Println("[+] Press Ctrl+C to gracefully terminate the scheduler daemon.")

	<-ctx.Done()

	fmt.Println("\n[*] Received shutdown signal. Waiting for active assessments to finish...")
	if err := sched.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Shutdown warning: %v\n", err)
	}
	fmt.Println("[+] Scheduler daemon stopped cleanly.")
	return 0
}
