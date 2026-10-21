package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runComplianceMTTR(args []string) int {
	var (
		dbPath          string
		fromStr         string
		toStr           string
		dateBasis       string
		severity        string
		category        string
		source          string
		assessmentID    string
		controlID       string
		policyID        string
		policyVersion   string
		strictIntegrity bool
		keyFilePath     string
		keyEnvVar       string
		keyID           string
		showSLA         bool
		jsonOutput      bool
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--from":
			if i+1 < len(args) {
				fromStr = args[i+1]
				i++
			}
		case "--to":
			if i+1 < len(args) {
				toStr = args[i+1]
				i++
			}
		case "--date-basis":
			if i+1 < len(args) {
				dateBasis = strings.ToLower(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--severity":
			if i+1 < len(args) {
				severity = strings.ToUpper(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--category":
			if i+1 < len(args) {
				category = strings.TrimSpace(args[i+1])
				i++
			}
		case "--source":
			if i+1 < len(args) {
				source = strings.TrimSpace(args[i+1])
				i++
			}
		case "--assessment":
			if i+1 < len(args) {
				assessmentID = strings.TrimSpace(args[i+1])
				i++
			}
		case "--control":
			if i+1 < len(args) {
				controlID = strings.TrimSpace(args[i+1])
				i++
			}
		case "--policy":
			if i+1 < len(args) {
				policyID = strings.TrimSpace(args[i+1])
				i++
			}
		case "--policy-version":
			if i+1 < len(args) {
				policyVersion = strings.TrimSpace(args[i+1])
				i++
			}
		case "--strict-integrity":
			strictIntegrity = true
		case "--key-file", "--key":
			if i+1 < len(args) {
				keyFilePath = args[i+1]
				i++
			}
		case "--key-env":
			if i+1 < len(args) {
				keyEnvVar = args[i+1]
				i++
			}
		case "--key-id":
			if i+1 < len(args) {
				keyID = args[i+1]
				i++
			}
		case "--sla":
			showSLA = true
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printMTTRHelp()
			return clierror.ExitSuccess
		default:
			fmt.Fprintf(os.Stderr, "[-] Unknown option for 'mttr': %s\n\n", args[i])
			printMTTRHelp()
			return clierror.ExitOperational
		}
	}

	// Parse date range
	var fromTime, toTime *time.Time
	if fromStr != "" {
		t, err := parseDateFlag(fromStr, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid --from date %q: %v\n", fromStr, err)
			return clierror.ExitOperational
		}
		fromTime = &t
	}
	if toStr != "" {
		t, err := parseDateFlag(toStr, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid --to date %q: %v\n", toStr, err)
			return clierror.ExitOperational
		}
		toTime = &t
	}

	if fromTime != nil && toTime != nil && fromTime.After(*toTime) {
		fmt.Fprintf(os.Stderr, "[-] Invalid date range: --from (%v) is after --to (%v)\n", fromStr, toStr)
		return clierror.ExitOperational
	}

	var dBasis compliance.MTTRDateBasis
	if dateBasis == "start" {
		dBasis = compliance.DateBasisStart
	} else {
		dBasis = compliance.DateBasisCompletion
	}

	// Resolve key provider if key credentials specified
	var keyProvider compliance.KeyProvider
	if keyFilePath != "" {
		if keyID == "" {
			keyID = filepath.Base(keyFilePath)
		}
		kp := compliance.NewFileKeyProvider(keyFilePath, keyID)
		if _, err := kp.GetVerificationKey(context.Background(), keyID); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid key configuration: %v\n", err)
			return clierror.ExitOperational
		}
		keyProvider = kp
	} else if keyEnvVar != "" {
		keyProvider = compliance.NewEnvKeyProvider(keyEnvVar)
	} else if os.Getenv("FELIX_COMPLIANCE_SIGNING_KEY") != "" || os.Getenv("FELIX_COMPLIANCE_KEY") != "" {
		envVar := "FELIX_COMPLIANCE_SIGNING_KEY"
		if os.Getenv(envVar) == "" {
			envVar = "FELIX_COMPLIANCE_KEY"
		}
		keyProvider = compliance.NewEnvKeyProvider(envVar)
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	svc := compliance.NewMTTRService(store, nil)
	filter := compliance.MTTRFilter{
		From:            fromTime,
		To:              toTime,
		DateBasis:       dBasis,
		Severity:        severity,
		FindingCategory: category,
		FindingSource:   source,
		AssessmentID:    assessmentID,
		ControlID:       controlID,
		PolicyID:        policyID,
		PolicyVersion:   policyVersion,
		StrictIntegrity: strictIntegrity,
		KeyProvider:     keyProvider,
	}

	result, err := svc.CalculateMTTR(context.Background(), filter)
	if err != nil {
		if strings.Contains(err.Error(), "integrity mismatch") || strings.Contains(err.Error(), "tampering") {
			if jsonOutput {
				out := map[string]any{
					"status": "INTEGRITY_MISMATCH",
					"error":  err.Error(),
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "[!] Integrity verification failure: %v\n", err)
			}
			return clierror.ExitSecurityFail
		}
		fmt.Fprintf(os.Stderr, "[-] Operational error calculating MTTR: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error formatting JSON result: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Println(string(b))
		return clierror.ExitSuccess
	}

	// Formatted human-readable output
	printMTTRSummary(result, showSLA)
	return clierror.ExitSuccess
}

func printMTTRHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance mttr [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  --from <date>             Filter by start or completion date (RFC3339 or YYYY-MM-DD)")
	fmt.Println("  --to <date>               Filter by start or completion date (RFC3339 or YYYY-MM-DD)")
	fmt.Println("  --date-basis <completion|start>")
	fmt.Println("                            Timestamp basis for date range filter (default: completion)")
	fmt.Println("  --severity <level>        Filter by finding severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	fmt.Println("  --category <category>     Filter by finding category (e.g. authz, injection)")
	fmt.Println("  --source <source>         Filter by finding source (e.g. apisec, webvuln)")
	fmt.Println("  --assessment <id>         Filter by assessment identifier")
	fmt.Println("  --control <id>            Filter by compliance control identifier (e.g. AC-3)")
	fmt.Println("  --policy <id>             Filter by remediation SLA policy ID")
	fmt.Println("  --policy-version <ver>    Filter by policy version")
	fmt.Println("  --strict-integrity        Fail immediately if any evaluation fails integrity verification")
	fmt.Println("  --key-file <path>         Path to file containing HMAC verification key")
	fmt.Println("  --key-env <var>           Environment variable containing verification key")
	fmt.Println("  --sla                     Display SLA deadline performance comparison")
	fmt.Println("  --db <path>               Custom compliance database path")
	fmt.Println("  --json                    Output machine-readable JSON")
	fmt.Println("  --help, -h                Show help")
}

func parseDateFlag(val string, endOfDay bool) (time.Time, error) {
	val = strings.TrimSpace(val)
	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, val); err == nil {
		return t.UTC(), nil
	}
	// Try YYYY-MM-DD
	if t, err := time.Parse("2006-01-02", val); err == nil {
		if endOfDay {
			return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, time.UTC), nil
		}
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD format (got %q)", val)
}

func printMTTRSummary(res *compliance.MTTRResult, showSLA bool) {
	fmt.Println("================================================================================")
	fmt.Println(" FELIX COMPLIANCE — MEAN TIME TO REMEDIATION (MTTR)")
	fmt.Println("================================================================================")

	if !res.HasData {
		fmt.Println("[*] Status: NO_DATA")
		fmt.Println("    No eligible completed remediation episodes match the specified filter.")
		fmt.Printf("    Excluded In-Progress: %d | Excluded Accepted Risk: %d | Other Excluded: %d\n",
			res.Exclusions.OpenOrInProgress, res.Exclusions.AcceptedRisk, res.Exclusions.TotalExcludedRecords)
		fmt.Println("================================================================================")
		return
	}

	fmt.Printf("[*] Mean Time to Remediation (MTTR) : %s\n", res.MTTRString)
	fmt.Printf("    Completed Episodes              : %d\n", res.CompletedEpisodes)
	fmt.Printf("    Unique Findings Represented     : %d\n", res.UniqueFindings)
	fmt.Printf("    Total Remediation Time          : %s\n", res.TotalDurationString)
	if res.MedianDuration != nil {
		fmt.Printf("    Median Remediation Time         : %s\n", res.MedianDurationString)
	}
	if res.MinDuration != nil && res.MaxDuration != nil {
		fmt.Printf("    Duration Range (Min / Max)      : %s / %s\n", res.MinDurationString, res.MaxDurationString)
	}
	fmt.Printf("    Coverage / Verification Status  : %s\n", res.CoverageStatus)

	if showSLA && res.SLAPerformance != nil {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println(" SLA PERFORMANCE COMPARISON")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("    Eligible With SLA Deadline      : %d\n", res.SLAPerformance.VerifiableEpisodes)
		fmt.Printf("    Completed On-Time (Within SLA)  : %d\n", res.SLAPerformance.CompletedOnTime)
		fmt.Printf("    Completed Late (Missed SLA)     : %d\n", res.SLAPerformance.CompletedLate)
		fmt.Printf("    SLA On-Time Completion Rate     : %.1f%%\n", res.SLAPerformance.OnTimeRate)
		if res.SLAPerformance.MissingDeadlineEpisodes > 0 {
			fmt.Printf("    Excluded (Missing SLA Deadline) : %d\n", res.SLAPerformance.MissingDeadlineEpisodes)
		}
		if res.SLAPerformance.CurrentOpenOverdue > 0 {
			fmt.Printf("    Current Open Overdue Items      : %d\n", res.SLAPerformance.CurrentOpenOverdue)
		}
	}

	if res.Exclusions.TotalExcludedRecords > 0 {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println(" EXCLUDED RECORDS & DATA COMPLETENESS")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("    Open / In-Progress (Not Done)   : %d\n", res.Exclusions.OpenOrInProgress)
		fmt.Printf("    Accepted Risk (Not Remediated)  : %d\n", res.Exclusions.AcceptedRisk)
		if res.Exclusions.MissingHistory > 0 {
			fmt.Printf("    Missing Completion History      : %d\n", res.Exclusions.MissingHistory)
		}
		if res.Exclusions.InvalidTimestamps > 0 {
			fmt.Printf("    Invalid Timestamp Sequences     : %d\n", res.Exclusions.InvalidTimestamps)
		}
		if res.Exclusions.IntegrityFailures > 0 {
			fmt.Printf("    Integrity Failures              : %d\n", res.Exclusions.IntegrityFailures)
		}
		if res.Exclusions.UnverifiedLegacy > 0 {
			fmt.Printf("    Unverified Legacy Evaluations   : %d\n", res.Exclusions.UnverifiedLegacy)
		}
	}

	fmt.Println("================================================================================")
}
