package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"felix/pkg/assessment"
)

func runAssessmentRecover(args []string) int {
	var execID string
	var asmRef string
	var dryRun bool
	var staleDurationStr string
	var maxRetries int = 3
	var allowResume bool
	var tenantID string
	var accountID string
	var asJSON bool
	var dbPath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--execution", "--execution-id", "-e":
			if i+1 < len(args) {
				execID = args[i+1]
				i++
			}
		case "--assessment", "--assessment-id", "-a":
			if i+1 < len(args) {
				asmRef = args[i+1]
				i++
			}
		case "--dry-run", "-n":
			dryRun = true
		case "--stale-duration", "-d":
			if i+1 < len(args) {
				staleDurationStr = args[i+1]
				i++
			}
		case "--max-retries", "-r":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					maxRetries = n
				}
				i++
			}
		case "--allow-resume":
			allowResume = true
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
			printRecoverHelp()
			return 0
		default:
			// If positional arg and not flag, treat as execution ID
			if len(args[i]) > 0 && args[i][0] != '-' && execID == "" {
				execID = args[i]
			}
		}
	}

	staleDur := 3 * time.Minute
	if staleDurationStr != "" {
		if d, err := time.ParseDuration(staleDurationStr); err == nil {
			staleDur = d
		} else if sec, err := strconv.Atoi(staleDurationStr); err == nil {
			staleDur = time.Duration(sec) * time.Second
		} else {
			fmt.Fprintf(os.Stderr, "[-] Invalid stale duration: %s\n", staleDurationStr)
			return 1
		}
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Store initialization error: %v\n", err)
		return 1
	}
	defer store.Close()

	auth := assessment.NewTenantAuthContext("", tenantID, accountID)
	if tenantID == "" && accountID == "" {
		auth = assessment.NewAdminAuthContext()
	}

	ctrl := assessment.NewController(store)
	opts := assessment.RecoveryOptions{
		Auth:          auth,
		ExecutionID:   execID,
		AssessmentID:  asmRef,
		DryRun:        dryRun,
		StaleDuration: staleDur,
		MaxRetries:    maxRetries,
		AllowResume:   allowResume,
		WorkerID:      "cli-recover",
		Runner:        ctrl.RunAssessment,
		Context:       context.Background(),
	}

	summary, err := store.RecoverExecutions(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Recovery sweep error: %v\n", err)
		return 1
	}

	if asJSON {
		b, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	if dryRun {
		fmt.Printf("[!] DRY RUN: Identified %d abandoned execution(s)\n\n", summary.ExaminedCount)
	} else {
		fmt.Printf("[+] Recovery sweep complete: %d examined, %d recovered (%d finalized, %d resumed), %d skipped, %d failed\n\n",
			summary.ExaminedCount, summary.RecoveredCount, summary.FinalizedCount, summary.ResumedCount, summary.SkippedCount, summary.FailedCount)
	}

	if len(summary.Results) == 0 {
		fmt.Println("No abandoned or interrupted executions found requiring recovery.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "EXECUTION ID\tASSESSMENT\tPREV STATUS\tNEW STATUS\tACTION\tFINDINGS\tREASON")
	for _, r := range summary.Results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			r.ExecutionID, r.AssessmentID, r.PreviousStatus, r.NewStatus, r.Action, r.PreservedFindings, r.Reason)
	}
	w.Flush()

	return 0
}

func printRecoverHelp() {
	fmt.Println("Usage: felix assessment recover [flags]")
	fmt.Println("       felix recover [flags]")
	fmt.Println("\nSafely recovers interrupted, abandoned, or crashed assessment executions.")
	fmt.Println("\nFlags:")
	fmt.Println("  --execution, -e <id>     Target a specific execution ID for recovery")
	fmt.Println("  --assessment, -a <ref>   Filter recovery to a specific assessment reference or ID")
	fmt.Println("  --dry-run, -n            Inspect abandoned executions without applying changes")
	fmt.Println("  --stale-duration, -d <t> Stale threshold before execution is deemed abandoned (default: 3m)")
	fmt.Println("  --max-retries, -r <n>    Maximum recovery attempts before permanent finalization (default: 3)")
	fmt.Println("  --allow-resume           Attempt safe resume if valid checkpoint exists (default: false)")
	fmt.Println("  --tenant <id>            Filter by tenant ID")
	fmt.Println("  --account <id>           Filter by account ID")
	fmt.Println("  --json                   Output summary in JSON format")
	fmt.Println("  --db <path>              Path to SQLite database file")
}
