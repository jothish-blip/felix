package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
	"felix/pkg/report"
)

func runComplianceEvaluate(args []string) int {
	var (
		catalogPath     string
		assessmentID    string
		mappingPath     string
		findingsPath    string
		evidencePath    string
		executionID     string
		status          string = "COMPLETED"
		saveResult      bool
		dbPath          string
		keyFilePath     string
		keyEnvVar       string
		keyID           string
		strictIntegrity bool
		jsonOutput      bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--catalog", "-c":
			if i+1 < len(args) {
				catalogPath = args[i+1]
				i++
			}
		case "--assessment", "-a":
			if i+1 < len(args) {
				assessmentID = args[i+1]
				i++
			}
		case "--mapping", "-m":
			if i+1 < len(args) {
				mappingPath = args[i+1]
				i++
			}
		case "--findings", "-f":
			if i+1 < len(args) {
				findingsPath = args[i+1]
				i++
			}
		case "--positive-evidence", "--evidence":
			if i+1 < len(args) {
				evidencePath = args[i+1]
				i++
			}
		case "--execution", "-e":
			if i+1 < len(args) {
				executionID = args[i+1]
				i++
			}
		case "--status":
			if i+1 < len(args) {
				status = strings.ToUpper(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--save":
			saveResult = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--key-file":
			if i+1 < len(args) {
				keyFilePath = args[i+1]
				i++
			}
		case "--key-env":
			if i+1 < len(args) {
				keyEnvVar = args[i+1]
				i++
			}
		case "--key", "-k":
			if i+1 < len(args) {
				val := args[i+1]
				i++
				if _, err := os.Stat(val); err == nil {
					keyFilePath = val
				} else {
					fmt.Fprintln(os.Stderr, "[-] Error: Passing raw key secrets directly via command-line arguments is disabled for security. Use --key-file <path> or set FELIX_COMPLIANCE_KEY.")
					return clierror.ExitOperational
				}
			}
		case "--key-id":
			if i+1 < len(args) {
				keyID = args[i+1]
				i++
			}
		case "--strict-integrity", "--strict":
			strictIntegrity = true
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printEvaluateHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if assessmentID == "" {
				assessmentID = arg
			}
		}
	}

	if catalogPath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --catalog <path> is required")
		return clierror.ExitOperational
	}
	if assessmentID == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --assessment <id> is required")
		return clierror.ExitOperational
	}

	// 1. Load Control Catalog
	catalog, err := compliance.LoadCatalog(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error loading catalog %q: %v\n", catalogPath, err)
		return clierror.ExitOperational
	}

	// 2. Load Findings (if provided)
	var findings []report.Finding
	if findingsPath != "" {
		f, err := loadFindingsFromFile(findingsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading findings from %q: %v\n", findingsPath, err)
			return clierror.ExitOperational
		}
		findings = f
	}

	// 3. Load Mapping RuleSet and Execute Mapping (if provided)
	var mappingResult *compliance.MappingResult
	if mappingPath != "" {
		ruleSet, err := compliance.LoadMappingRuleSet(mappingPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading mapping ruleset %q: %v\n", mappingPath, err)
			return clierror.ExitOperational
		}
		engine := compliance.NewMappingEngine()
		mRes, err := engine.MapFindings(catalog, ruleSet, findings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error executing finding mapping: %v\n", err)
			return clierror.ExitOperational
		}
		mappingResult = mRes
	}

	// 4. Load Positive Evidence (if provided)
	var positiveEvidence []compliance.PositiveEvidence
	if evidencePath != "" {
		pe, err := loadPositiveEvidenceFromFile(evidencePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading positive evidence from %q: %v\n", evidencePath, err)
			return clierror.ExitOperational
		}
		positiveEvidence = pe
	}

	// 5. Build Evaluation Context
	evalCtx := &compliance.EvaluationContext{
		AssessmentID:     assessmentID,
		ExecutionID:      executionID,
		AssessmentStatus: status,
		PositiveEvidence: positiveEvidence,
	}

	// 6. Execute Evaluation
	evaluator := compliance.NewEvaluationEngine()
	evalResult, err := evaluator.Evaluate(catalog, mappingResult, findings, evalCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Compliance evaluation failed: %v\n", err)
		return clierror.ExitOperational
	}

	// 7. Save to Store (if requested)
	var savedRecordID string
	if saveResult {
		store, err := compliance.NewSQLiteComplianceStore(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
			return clierror.ExitOperational
		}
		defer store.Close()

		kp, kpErr := resolveKeyProvider(keyFilePath, keyEnvVar, keyID)
		if kpErr != nil {
			if strictIntegrity {
				fmt.Fprintf(os.Stderr, "[-] Strict integrity mode failed: %v\n", kpErr)
				return clierror.ExitOperational
			}
		}

		if kp != nil {
			if err := store.SaveEvaluationResultWithKey(evalResult, kp); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error persisting evaluation result with integrity signature: %v\n", err)
				return clierror.ExitOperational
			}
		} else {
			if strictIntegrity {
				fmt.Fprintln(os.Stderr, "[-] Strict integrity mode failed: no verification key configured for signing")
				return clierror.ExitOperational
			}
			if err := store.SaveEvaluationResult(evalResult); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error persisting evaluation result: %v\n", err)
				return clierror.ExitOperational
			}
		}
		savedRecordID = evalResult.AssessmentID + ":" + catalog.Identity()
	}

	// 8. Output Results
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(evalResult)
	} else {
		fmt.Printf("=== FELIX Compliance Evaluation Result ===\n")
		fmt.Printf("Assessment ID:          %s\n", evalResult.AssessmentID)
		if evalResult.ExecutionID != "" {
			fmt.Printf("Execution ID:           %s\n", evalResult.ExecutionID)
		}
		fmt.Printf("Catalog Identity:       %s\n", evalResult.CatalogIdentity)
		fmt.Printf("Catalog Digest:         %s\n", evalResult.CatalogDigest)
		if evalResult.MappingRuleSetIdentity != "" {
			fmt.Printf("Mapping RuleSet:        %s\n", evalResult.MappingRuleSetIdentity)
		}
		fmt.Printf("Evaluated At:           %s\n", evalResult.EvaluatedAt.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("Result Digest (SHA256): %s\n", evalResult.Digest())
		if savedRecordID != "" {
			fmt.Printf("Persisted To Store:     %s\n", savedRecordID)
		}

		sum := evalResult.Summary
		fmt.Printf("\nControl Evaluation Breakdown (%d Total Controls):\n", sum.TotalControls)
		fmt.Printf("  [+] Compliant:             %d\n", sum.CompliantCount)
		fmt.Printf("  [-] Non-Compliant:         %d\n", sum.NonCompliantCount)
		fmt.Printf("  [~] Partially Compliant:   %d\n", sum.PartiallyCompliantCount)
		fmt.Printf("  [?] Insufficient Evidence: %d\n", sum.InsufficientEvidenceCount)
		fmt.Printf("  [ ] Not Assessed:          %d\n", sum.NotAssessedCount)
		fmt.Printf("  [*] Not Applicable:        %d\n", sum.NotApplicableCount)
		if sum.ErrorCount > 0 {
			fmt.Printf("  [!] Execution Error:       %d\n", sum.ErrorCount)
		}

		if len(evalResult.Evaluations) > 0 {
			fmt.Printf("\nEvaluated Controls Summary:\n")
			fmt.Printf("%-12s  %-22s  %s\n", "CONTROL ID", "EVALUATION STATE", "RATIONALE")
			fmt.Printf("%-12s  %-22s  %s\n", "----------", "----------------", "---------")
			for _, ce := range evalResult.Evaluations {
				fmt.Printf("%-12s  %-22s  %s\n", ce.ControlID, string(ce.State), ce.Rationale)
			}
		}

		cov := compliance.CalculateCoverageBasis(sum)
		fmt.Printf("\nAssessment Coverage Basis:\n")
		fmt.Printf("  Scope Basis:               %s\n", cov.DenominatorDescription)
		fmt.Printf("  Assessed Coverage:         %d / %d applicable controls (%.1f%%)\n", cov.AssessedControls, cov.ApplicableControls, cov.AssessedCoveragePercent)
		fmt.Printf("  Verified Compliance Rate:  %d / %d applicable controls (%.1f%%)\n", sum.CompliantCount, cov.ApplicableControls, cov.ComplianceRatePercent)

		fmt.Printf("\nLimitations Notice:\n  %s\n", evalResult.LimitationsNotice)
	}

	// 9. Exit Code Contract
	// Exit 2: Incomplete or failed assessment status
	if status != "COMPLETED" && status != "COMPLETED_WITH_ERRORS" {
		return clierror.ExitOperational
	}
	// Exit 1: Trustworthy completed evaluation establishes compliance violations
	if evalResult.Summary.NonCompliantCount > 0 {
		return clierror.ExitSecurityFail
	}
	// Exit 1: Partial compliance represents unsatisfied requirements
	if evalResult.Summary.PartiallyCompliantCount > 0 {
		return clierror.ExitSecurityFail
	}
	// If zero controls were compliant and there are unassessed or insufficient controls,
	// compliance was not established.
	if evalResult.Summary.CompliantCount == 0 && evalResult.Summary.TotalControls > 0 {
		return clierror.ExitSecurityFail
	}

	return clierror.ExitSuccess
}

func printEvaluateHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance evaluate [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  --catalog <path>, -c <path>   Path to ControlCatalog JSON file (required)")
	fmt.Println("  --assessment <id>, -a <id>    Assessment ID to evaluate (required)")
	fmt.Println("  --mapping <path>, -m <path>   Path to MappingRuleSet JSON file")
	fmt.Println("  --findings <path>, -f <path>  Path to assessment findings JSON file")
	fmt.Println("  --evidence <path>             Path to positive evidence JSON file")
	fmt.Println("  --execution <id>, -e <id>     Execution ID")
	fmt.Println("  --status <status>             Assessment status (default: COMPLETED)")
	fmt.Println("  --save                        Persist the evaluation result into compliance store")
	fmt.Println("  --db <path>                   Custom SQLite compliance database path")
	fmt.Println("  --key-file <path>             Path to HMAC signing/verification key")
	fmt.Println("  --key-env <var>               Environment variable containing signing key")
	fmt.Println("  --strict-integrity, --strict  Fail closed if signing key is missing or invalid")
	fmt.Println("  --json                        Output machine-readable JSON")
	fmt.Println("  --help, -h                    Show help")
}

func runComplianceEvaluation(args []string) int {
	if len(args) == 0 {
		printEvaluationHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		return runEvaluationList(subArgs)
	case "view", "get", "show":
		return runEvaluationView(subArgs)
	case "controls", "list-controls":
		return runEvaluationControls(subArgs)
	case "evidence":
		return runEvaluationEvidence(subArgs)
	case "help", "--help", "-h":
		printEvaluationHelp()
		return clierror.ExitSuccess
	default:
		// If first arg doesn't look like a subcommand, treat as 'view <id>'
		if !strings.HasPrefix(sub, "-") {
			return runEvaluationView(args)
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown evaluation subcommand: %s\n\n", sub)
		printEvaluationHelp()
		return clierror.ExitOperational
	}
}

func printEvaluationHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance evaluation <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  list                          List persisted compliance evaluation results")
	fmt.Println("  view <assessment-id>          View details of a persisted evaluation result")
	fmt.Println("  controls                      List individual control evaluation records")
	fmt.Println("  evidence <evaluation-id>      Inspect stored evidence linked to a control evaluation")
	fmt.Println("  help                          Display this help message")
	fmt.Println("\nOptions for 'list':")
	fmt.Println("  --assessment <id>             Filter by assessment ID")
	fmt.Println("  --catalog <id>                Filter by catalog ID")
	fmt.Println("  --limit <n>                   Maximum records to return (default: 50)")
	fmt.Println("  --offset <n>                  Pagination offset")
	fmt.Println("  --db <path>                   Custom compliance database path")
	fmt.Println("  --json                        Output machine-readable JSON")
	fmt.Println("\nOptions for 'view':")
	fmt.Println("  --catalog <id>                Catalog ID to disambiguate multiple evaluations")
	fmt.Println("  --key-file <path>             Path to HMAC key file to verify record integrity")
	fmt.Println("  --key-env <var>               Environment variable containing verification key")
	fmt.Println("  --db <path>                   Custom compliance database path")
	fmt.Println("  --json                        Output machine-readable JSON")
	fmt.Println("\nOptions for 'controls':")
	fmt.Println("  --assessment <id>             Filter by assessment ID")
	fmt.Println("  --catalog <id>                Filter by catalog ID")
	fmt.Println("  --control <id>                Filter by specific control ID")
	fmt.Println("  --state <state>               Filter by evaluation state (compliant, non_compliant, etc.)")
	fmt.Println("  --limit <n>                   Maximum records to return (default: 100)")
	fmt.Println("  --db <path>                   Custom compliance database path")
	fmt.Println("  --json                        Output machine-readable JSON")
}

func runEvaluationList(args []string) int {
	var (
		filter     compliance.EvaluationResultFilter
		dbPath     string
		jsonOutput bool
	)
	filter.Limit = 50

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "-a":
			if i+1 < len(args) {
				filter.AssessmentID = args[i+1]
				i++
			}
		case "--catalog", "-c":
			if i+1 < len(args) {
				filter.CatalogID = args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				filter.Limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--offset":
			if i+1 < len(args) {
				filter.Offset, _ = strconv.Atoi(args[i+1])
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
			printEvaluationHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
		}
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	results, err := store.ListEvaluationResults(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error listing evaluations: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		fmt.Printf("=== Persisted Compliance Evaluations (%d found) ===\n\n", len(results))
		if len(results) == 0 {
			fmt.Println("No evaluation records match query criteria.")
			return clierror.ExitSuccess
		}
		fmt.Printf("%-20s  %-24s  %-19s  %-6s  %-6s  %s\n", "ASSESSMENT ID", "CATALOG", "EVALUATED AT", "TOTAL", "FAIL", "DIGEST")
		fmt.Printf("%-20s  %-24s  %-19s  %-6s  %-6s  %s\n", "-------------", "-------", "------------", "-----", "----", "------")
		for _, r := range results {
			catName := r.CatalogIdentity
			if len(catName) > 24 {
				catName = catName[:21] + "..."
			}
			dig := r.ResultDigest
			if len(dig) > 16 {
				dig = dig[:16] + "..."
			}
			evalAt := r.EvaluatedAt.Format("2006-01-02 15:04:05")
			fmt.Printf("%-20s  %-24s  %-19s  %-6d  %-6d  %s\n",
				r.AssessmentID, catName, evalAt, r.Summary.TotalControls, r.Summary.NonCompliantCount, dig)
		}
	}

	return clierror.ExitSuccess
}

func runEvaluationView(args []string) int {
	var (
		assessmentID string
		catalogID    string
		dbPath       string
		keyFilePath  string
		keyEnvVar    string
		keyID        string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--catalog", "-c":
			if i+1 < len(args) {
				catalogID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--key-file":
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
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printEvaluationHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if assessmentID == "" {
				assessmentID = arg
			}
		}
	}

	if assessmentID == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: assessment ID is required")
		return clierror.ExitOperational
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	kp, _ := resolveKeyProvider(keyFilePath, keyEnvVar, keyID)

	eval, err := store.GetEvaluationResult(assessmentID, catalogID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error retrieving evaluation for assessment %q: %v\n", assessmentID, err)
		return clierror.ExitOperational
	}

	var integResult *compliance.IntegrityVerificationResult
	if kp != nil {
		integ, err := store.VerifyEvaluationIntegrity(assessmentID, catalogID, kp)
		if err == nil {
			integResult = integ
		}
	}

	if jsonOutput {
		out := map[string]any{
			"evaluation": eval,
		}
		if integResult != nil {
			out["integrity"] = integResult
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Printf("=== FELIX Evaluation Record ===\n")
		fmt.Printf("Assessment ID:          %s\n", eval.AssessmentID)
		if eval.ExecutionID != "" {
			fmt.Printf("Execution ID:           %s\n", eval.ExecutionID)
		}
		fmt.Printf("Catalog Identity:       %s\n", eval.CatalogIdentity)
		fmt.Printf("Catalog Digest:         %s\n", eval.CatalogDigest)
		if eval.MappingRuleSetIdentity != "" {
			fmt.Printf("Mapping RuleSet:        %s\n", eval.MappingRuleSetIdentity)
		}
		fmt.Printf("Evaluated At:           %s\n", eval.EvaluatedAt.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("Engine Version:         %s\n", eval.EngineVersion)
		fmt.Printf("Result Digest:          %s\n", eval.Digest())

		if integResult != nil {
			fmt.Printf("\nIntegrity Verification: %s (HMAC: %t, Digest: %t)\n",
				integResult.Status, integResult.AuthenticityMatch, integResult.ContentDigestMatch)
		}

		sum := eval.Summary
		fmt.Printf("\nEvaluation Summary (%d Total Controls):\n", sum.TotalControls)
		fmt.Printf("  [+] Compliant:             %d\n", sum.CompliantCount)
		fmt.Printf("  [-] Non-Compliant:         %d\n", sum.NonCompliantCount)
		fmt.Printf("  [~] Partially Compliant:   %d\n", sum.PartiallyCompliantCount)
		fmt.Printf("  [?] Insufficient Evidence: %d\n", sum.InsufficientEvidenceCount)
		fmt.Printf("  [ ] Not Assessed:          %d\n", sum.NotAssessedCount)
		fmt.Printf("  [*] Not Applicable:        %d\n", sum.NotApplicableCount)
		if sum.ErrorCount > 0 {
			fmt.Printf("  [!] Execution Error:       %d\n", sum.ErrorCount)
		}

		if len(eval.Evaluations) > 0 {
			fmt.Printf("\nControl Evaluation Records (%d):\n", len(eval.Evaluations))
			for _, ce := range eval.Evaluations {
				fmt.Printf("  - %-10s  %-20s  %s\n", ce.ControlID, string(ce.State), ce.Rationale)
			}
		}

		fmt.Printf("\nLimitations Notice:\n  %s\n", eval.LimitationsNotice)
	}

	if eval.Summary.NonCompliantCount > 0 || eval.Summary.PartiallyCompliantCount > 0 {
		return clierror.ExitSecurityFail
	}
	return clierror.ExitSuccess
}

func runEvaluationControls(args []string) int {
	var (
		filter     compliance.EvaluationFilter
		dbPath     string
		jsonOutput bool
	)
	filter.Limit = 100

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "-a":
			if i+1 < len(args) {
				filter.AssessmentID = args[i+1]
				i++
			}
		case "--catalog", "-c":
			if i+1 < len(args) {
				filter.CatalogID = args[i+1]
				i++
			}
		case "--control":
			if i+1 < len(args) {
				filter.ControlID = args[i+1]
				i++
			}
		case "--state", "-s":
			if i+1 < len(args) {
				rawState := args[i+1]
				i++
				canon, ok := compliance.CanonicalEvaluationState(rawState)
				if !ok {
					fmt.Fprintf(os.Stderr, "[-] Error: invalid evaluation state %q (must be compliant, non_compliant, partially_compliant, not_assessed, insufficient_evidence, not_applicable, or error)\n", rawState)
					return clierror.ExitOperational
				}
				filter.State = canon
			}
		case "--limit":
			if i+1 < len(args) {
				filter.Limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--offset":
			if i+1 < len(args) {
				filter.Offset, _ = strconv.Atoi(args[i+1])
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
			printEvaluationHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
		}
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	records, err := store.ListControlEvaluations(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error querying control evaluations: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(records)
	} else {
		fmt.Printf("=== Control Evaluation Records (%d found) ===\n\n", len(records))
		if len(records) == 0 {
			fmt.Println("No control records match query criteria.")
			return clierror.ExitSuccess
		}
		fmt.Printf("%-12s  %-20s  %-18s  %-12s  %s\n", "CONTROL ID", "STATE", "ASSESSMENT ID", "EVALUATED AT", "RATIONALE")
		fmt.Printf("%-12s  %-20s  %-18s  %-12s  %s\n", "----------", "-----", "-------------", "------------", "---------")
		for _, r := range records {
			evalAt := r.EvaluatedAt.Format("2006-01-02")
			rat := r.Rationale
			if len(rat) > 40 {
				rat = rat[:37] + "..."
			}
			fmt.Printf("%-12s  %-20s  %-18s  %-12s  %s\n", r.ControlID, string(r.State), r.AssessmentID, evalAt, rat)
		}
	}

	return clierror.ExitSuccess
}

func runEvaluationEvidence(args []string) int {
	var (
		evaluationID string
		dbPath       string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printEvaluationHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if evaluationID == "" {
				evaluationID = arg
			}
		}
	}

	if evaluationID == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: evaluation ID is required")
		return clierror.ExitOperational
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	evidence, err := store.GetEvaluationEvidence(evaluationID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error querying evidence for evaluation %q: %v\n", evaluationID, err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(evidence)
	} else {
		fmt.Printf("=== Evidence for Evaluation %s (%d items) ===\n\n", evaluationID, len(evidence))
		if len(evidence) == 0 {
			fmt.Println("No evidence records linked to this control evaluation.")
			return clierror.ExitSuccess
		}
		fmt.Printf("%-24s  %-12s  %-14s  %-20s  %s\n", "EVIDENCE ID", "CONTROL ID", "TYPE", "REFERENCE ID", "DETAIL")
		fmt.Printf("%-24s  %-12s  %-14s  %-20s  %s\n", "-----------", "----------", "----", "------------", "------")
		for _, e := range evidence {
			det := e.Detail
			if len(det) > 40 {
				det = det[:37] + "..."
			}
			refID := e.ReferenceID
			if len(refID) > 20 {
				refID = refID[:17] + "..."
			}
			fmt.Printf("%-24s  %-12s  %-14s  %-20s  %s\n", e.ID, e.ControlID, e.EvidenceType, refID, det)
		}
	}

	return clierror.ExitSuccess
}

func loadPositiveEvidenceFromFile(path string) ([]compliance.PositiveEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty positive evidence file")
	}

	var list []compliance.PositiveEvidence
	if err := json.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return list, nil
	}

	var container struct {
		PositiveEvidence []compliance.PositiveEvidence `json:"positive_evidence"`
	}
	if err := json.Unmarshal(data, &container); err == nil && len(container.PositiveEvidence) > 0 {
		return container.PositiveEvidence, nil
	}

	return nil, fmt.Errorf("file does not contain valid PositiveEvidence JSON array or container")
}

func resolveKeyProvider(keyFilePath, keyEnvVar, keyID string) (compliance.KeyProvider, error) {
	if keyFilePath != "" {
		if keyID == "" {
			keyID = filepath.Base(keyFilePath)
		}
		kp := compliance.NewFileKeyProvider(keyFilePath, keyID)
		if _, err := kp.GetVerificationKey(context.Background(), keyID); err != nil {
			return nil, fmt.Errorf("invalid key file: %w", err)
		}
		return kp, nil
	}
	if keyEnvVar != "" {
		kp := compliance.NewEnvKeyProvider(keyEnvVar)
		if _, err := kp.GetVerificationKey(context.Background(), ""); err != nil {
			return nil, fmt.Errorf("invalid key env var %q: %w", keyEnvVar, err)
		}
		return kp, nil
	}
	envVar := "FELIX_COMPLIANCE_SIGNING_KEY"
	if os.Getenv(envVar) == "" {
		envVar = "FELIX_COMPLIANCE_KEY"
	}
	if os.Getenv(envVar) != "" {
		kp := compliance.NewEnvKeyProvider(envVar)
		return kp, nil
	}
	return nil, nil
}
