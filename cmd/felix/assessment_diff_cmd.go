package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
)

func runAssessmentDiff(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printDiffHelp()
		return 0
	}

	var positional []string
	var (
		format      string = "table"
		jsonOutput  bool
		summaryOnly bool
		role        string = "admin"
		clientID    string
		tenantID    string
		accountID   string
		dbPath      string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOutput = true
			format = "json"
		case "--format":
			if i+1 < len(args) {
				format = strings.ToLower(args[i+1])
				i++
			}
		case "--summary-only", "--summary":
			summaryOnly = true
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
		case "--help", "-h":
			printDiffHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") {
				positional = append(positional, arg)
			}
		}
	}

	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "[-] Error: baseline and current identifiers are required (e.g. felix assessment diff <baseline-id> <current-id>)")
		printDiffHelp()
		return 2
	}

	baselineRef := positional[0]
	currentRef := positional[1]

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

	// Resolve identifiers: try Execution, Snapshot, or Assessment
	baseExecID, baseSnapID, err := resolveRefToExecOrSnapshot(store, baselineRef, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve baseline %q: %v\n", baselineRef, err)
		return 2
	}

	currExecID, currSnapID, err := resolveRefToExecOrSnapshot(store, currentRef, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to resolve current %q: %v\n", currentRef, err)
		return 2
	}

	var cmp *correlation.AssessmentComparison
	if baseExecID != "" && currExecID != "" {
		cmp, err = store.CompareExecutionHistory(baseExecID, currExecID, authCtx)
	} else if baseSnapID != "" && currSnapID != "" {
		cmp, err = store.CompareSnapshots(baseSnapID, currSnapID, authCtx)
	} else {
		// Fallback to CompareExecutionHistory or CompareSnapshots
		if baseSnapID != "" && currSnapID != "" {
			cmp, err = store.CompareSnapshots(baseSnapID, currSnapID, authCtx)
		} else {
			cmp, err = store.CompareExecutionHistory(baselineRef, currentRef, authCtx)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Comparison failed: %v\n", err)
		return 2
	}

	if jsonOutput || format == "json" {
		data, err := json.MarshalIndent(cmp, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to format JSON output: %v\n", err)
			return 2
		}
		fmt.Println(string(data))
		return 0
	}

	printDiffReport(cmp, summaryOnly)
	return 0
}

func printDiffHelp() {
	fmt.Println("Usage: felix assessment diff <baseline-id> <current-id> [flags]")
	fmt.Println("       felix diff <baseline-id> <current-id> [flags]")
	fmt.Println("\nArguments:")
	fmt.Println("  <baseline-id>   Execution ID, snapshot ID, or assessment ID of baseline run")
	fmt.Println("  <current-id>    Execution ID, snapshot ID, or assessment ID of current run")
	fmt.Println("\nFlags:")
	fmt.Println("  --json             Output diff results as structured JSON")
	fmt.Println("  --format <fmt>     Output format: table (default), text, json")
	fmt.Println("  --summary-only     Display only summary statistics and delta counts")
	fmt.Println("  --role <role>      Authorization role (admin, client, auditor; default: admin)")
	fmt.Println("  --client <id>      Client identifier for tenant isolation")
	fmt.Println("  --tenant <id>      Tenant identifier for multi-tenant boundary checks")
	fmt.Println("  --account <id>     Account identifier")
	fmt.Println("  --db <path>        Path to SQLite assessment database")
}

func resolveRefToExecOrSnapshot(store *assessment.SQLiteStore, ref string, auth assessment.TenantAuthContext) (execID string, snapID string, err error) {
	// 1. Try execution record
	if exec, err := store.GetExecutionHistory(ref, auth); err == nil && exec != nil {
		return exec.ID, exec.SnapshotID, nil
	}

	// 2. Try snapshot record
	if snap, err := store.GetSnapshot(ref, auth); err == nil && snap != nil {
		return snap.ExecutionID, snap.ID, nil
	}

	// 3. Try assessment ID -> list latest executions
	if execs, err := store.ListExecutions(ref); err == nil && len(execs) > 0 {
		return execs[0].ID, execs[0].SnapshotID, nil
	}

	// If not resolvable directly, assume ref is an execution ID and let store report precise error
	return ref, "", nil
}

func printDiffReport(cmp *correlation.AssessmentComparison, summaryOnly bool) {
	fmt.Println("================================================================================")
	fmt.Println("FELIX ASSESSMENT FINDING DELTA")
	fmt.Println("================================================================================")
	if cmp.BaselineExecutionID != "" {
		fmt.Printf("Baseline Execution: %s", cmp.BaselineExecutionID)
		if cmp.BaselineSnapshotID != "" {
			fmt.Printf(" (Snapshot: %s)", cmp.BaselineSnapshotID)
		}
		fmt.Println()
	}
	if cmp.CurrentExecutionID != "" {
		fmt.Printf("Current Execution:  %s", cmp.CurrentExecutionID)
		if cmp.CurrentSnapshotID != "" {
			fmt.Printf(" (Snapshot: %s)", cmp.CurrentSnapshotID)
		}
		fmt.Println()
	}
	fmt.Printf("Comparison Status:  %s\n", cmp.ComparisonStatus)
	if cmp.ComparisonReason != "" {
		fmt.Printf("Status Reason:      %s\n", cmp.ComparisonReason)
	}

	fmt.Println("\nSummary Statistics:")
	fmt.Printf("  Baseline Findings:   %d\n", cmp.BaselineCount)
	fmt.Printf("  Current Findings:    %d\n", cmp.CurrentCount)
	fmt.Printf("  New Findings:        %d\n", cmp.NewCount)
	fmt.Printf("  Persistent Findings: %d\n", cmp.PersistentCount)
	fmt.Printf("  Changed Findings:    %d\n", cmp.ChangedCount)
	fmt.Printf("  Resolved Findings:   %d\n", cmp.ResolvedCount)
	fmt.Printf("  Regressed Findings:  %d\n", cmp.RegressedCount)
	fmt.Printf("  Unverified Findings: %d\n", cmp.UnverifiedCount)
	scoreSign := ""
	if cmp.NetRiskScoreDelta > 0 {
		scoreSign = "+"
	}
	fmt.Printf("  Net Risk Score:      %s%d\n", scoreSign, cmp.NetRiskScoreDelta)

	if summaryOnly || len(cmp.Items) == 0 {
		return
	}

	fmt.Println("\nFINDING CLASSIFICATIONS:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CLASSIFICATION\tSEVERITY\tTITLE\tREASON / CHANGE\tTARGET\tFINGERPRINT")
	fmt.Fprintln(w, "--------------\t--------\t-----\t---------------\t------\t-----------")

	for _, it := range cmp.Items {
		reason := "-"
		if it.RegressionReason != "" {
			reason = "REGRESSION: " + it.RegressionReason
		} else if it.ChangeReason != "" {
			reason = "CHANGE: " + it.ChangeReason
		}

		target := it.TargetEndpoint
		if target == "" && it.CurrentFinding != nil {
			target = it.CurrentFinding.Target
		}
		if target == "" && it.BaselineFinding != nil {
			target = it.BaselineFinding.Target
		}
		if len(target) > 30 {
			target = target[:27] + "..."
		}

		fpShort := it.Fingerprint
		if len(fpShort) > 16 {
			fpShort = fpShort[:16] + "..."
		}

		title := it.Title
		if len(title) > 35 {
			title = title[:32] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			it.Classification, it.Severity, title, reason, target, fpShort,
		)
	}
	w.Flush()
}
