package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"felix/pkg/report"
)

func runAssessmentSummary(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printSummaryHelp()
		return 0
	}

	var positional []string
	var (
		assessmentID string
		baselineRef  string
		executionRef string
		format       string = "text"
		jsonOutput   bool
		role         string = "admin"
		clientID     string
		tenantID     string
		accountID    string
		dbPath       string
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
		case "--assessment-id", "--assessment", "--id":
			if i+1 < len(args) {
				assessmentID = args[i+1]
				i++
			}
		case "--baseline", "--base":
			if i+1 < len(args) {
				baselineRef = args[i+1]
				i++
			}
		case "--execution", "--current", "--exec":
			if i+1 < len(args) {
				executionRef = args[i+1]
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
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--help", "-h":
			printSummaryHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") {
				positional = append(positional, arg)
			}
		}
	}

	// Positional arguments fallback
	if assessmentID == "" && len(positional) > 0 {
		if len(positional) == 1 {
			assessmentID = positional[0]
		} else if len(positional) >= 2 {
			if baselineRef == "" && executionRef == "" {
				baselineRef = positional[0]
				executionRef = positional[1]
			} else if assessmentID == "" {
				assessmentID = positional[0]
				if executionRef == "" {
					executionRef = positional[1]
				}
			}
		}
	}

	if assessmentID == "" && executionRef == "" && baselineRef == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --assessment-id or --execution is required (e.g. felix assessment summary --assessment-id <id>)")
		printSummaryHelp()
		return 2
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

	summary, err := store.GetAssessmentChangeSummary(assessmentID, baselineRef, executionRef, authCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to generate change summary: %v\n", err)
		return 2
	}

	if jsonOutput || format == "json" {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to format JSON output: %v\n", err)
			return 2
		}
		fmt.Println(string(data))
		return 0
	}

	printSummaryReport(summary)
	return 0
}

func printSummaryHelp() {
	fmt.Println("Usage: felix assessment summary [flags]")
	fmt.Println("       felix summary [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --assessment-id <id>     Assessment ID to summarize")
	fmt.Println("  --baseline <exec-id>     Baseline execution ID or snapshot ID (optional; defaults to latest prior run)")
	fmt.Println("  --execution <exec-id>    Comparison execution ID or snapshot ID (optional; defaults to latest run)")
	fmt.Println("  --json                   Output summary as structured machine-readable JSON")
	fmt.Println("  --format <fmt>           Output format: text (default), json, table")
	fmt.Println("  --role <role>            Authorization role (admin, client, auditor; default: admin)")
	fmt.Println("  --client <id>            Client identifier for tenant isolation")
	fmt.Println("  --tenant <id>            Tenant identifier for multi-tenant boundary checks")
	fmt.Println("  --account <id>           Account identifier")
	fmt.Println("  --db <path>              Path to SQLite assessment database")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment summary --assessment-id asm-123")
	fmt.Println("  felix assessment summary --assessment-id asm-123 --baseline exec-1 --execution exec-2")
	fmt.Println("  felix assessment summary --assessment-id asm-123 --format json")
}

func printSummaryReport(cs *report.ChangeSummary) {
	fmt.Print(cs.FormatText())
}
