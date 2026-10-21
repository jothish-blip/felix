package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

// runComplianceGate routes "felix compliance gate" subcommands.
func runComplianceGate(args []string) int {
	if len(args) == 0 {
		printGateHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "validate":
		return runGateValidate(subArgs)
	case "inspect":
		return runGateInspect(subArgs)
	case "check", "evaluate":
		return runGateCheck(subArgs)
	case "help", "--help", "-h":
		printGateHelp()
		return clierror.ExitSuccess
	default:
		// If first arg starts with "-", treat as options for 'check'
		if strings.HasPrefix(sub, "-") {
			return runGateCheck(args)
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown gate subcommand %q\n\n", sub)
		printGateHelp()
		return clierror.ExitOperational
	}
}

func printGateHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance gate <subcommand> [options]")
	fmt.Println("  felix compliance gate --policy <file> --assessment <id> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  check, evaluate             Evaluate an assessment against a compliance gate policy")
	fmt.Println("  validate <file>             Validate a compliance gate policy for schema and semantics")
	fmt.Println("  inspect <file>              Inspect a compliance gate policy's configuration and thresholds")
	fmt.Println("  help                        Display this help message")
	fmt.Println("\nOptions for 'check' / 'evaluate':")
	fmt.Println("  --policy <path>, -p         Path to ComplianceGatePolicy JSON/YAML file (required)")
	fmt.Println("  --assessment <id>, -a       Assessment ID to evaluate (required unless --dossier-file is used)")
	fmt.Println("  --catalog <id>, -c          Catalog ID or identity (e.g. nist-sp800-53-sample)")
	fmt.Println("  --dossier-file <path>, -d   Path to a ComplianceDossier JSON file to evaluate directly")
	fmt.Println("  --evaluation-file <path>    Path to an EvaluationResult JSON file to evaluate directly")
	fmt.Println("  --status <status>           Assessment execution status (default: from record or COMPLETED)")
	fmt.Println("  --key-file <path>           Path to HMAC verification key file")
	fmt.Println("  --key-env <var>             Environment variable containing verification key")
	fmt.Println("  --key-id <id>               Key ID for multi-key verification providers")
	fmt.Println("  --strict-integrity, --strict Fail closed if cryptographic integrity cannot be verified")
	fmt.Println("  --db <path>                 Custom compliance database path")
	fmt.Println("  --output <path>, -o         Path to write gate decision report artifact")
	fmt.Println("  --format <json|text|md>     Report artifact format (default: json)")
	fmt.Println("  --overwrite                 Allow overwriting existing output artifact")
	fmt.Println("  --json                      Output machine-readable gate decision JSON on stdout")
	fmt.Println("  --help, -h                  Show help")
	fmt.Println("\nExit Codes:")
	fmt.Println("  0  PASS                 All policy conditions, thresholds, and integrity checks satisfied")
	fmt.Println("  1  POLICY FAILURE       Completed assessment established a compliance policy violation")
	fmt.Println("  2  OPERATIONAL FAILURE  Operational error, missing input, corrupt record, or incomplete scan")
}

func runGateValidate(args []string) int {
	var filePath string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance gate validate <policy.json|yaml> [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && filePath == "" {
				filePath = arg
			} else {
				fmt.Fprintf(os.Stderr, "[-] Unknown validate option: %s\n", arg)
				return clierror.ExitOperational
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: policy file path is required")
		return clierror.ExitOperational
	}

	pol, err := compliance.LoadGatePolicy(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Compliance gate policy validation FAILED for %q: %v\n", filePath, err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"valid":  true,
			"policy": pol,
		})
	} else {
		fmt.Printf("[+] Compliance gate policy %q is VALID\n", filePath)
		fmt.Printf("    ID:                     %s\n", pol.ID)
		fmt.Printf("    Version:                %s\n", pol.Version)
		if pol.Name != "" {
			fmt.Printf("    Name:                   %s\n", pol.Name)
		}
		if pol.TargetCatalog != "" {
			fmt.Printf("    Target Catalog:         %s\n", pol.TargetCatalog)
		}
		fmt.Printf("    Enforced Controls:      %d\n", len(pol.EnforcedControls))
		fmt.Printf("    Min Compliance %%:       %.2f%%\n", pol.GetMinCompliancePercent())
		fmt.Printf("    Min Assessed %%:         %.2f%%\n", pol.GetMinAssessedPercent())
		fmt.Printf("    Partially Compliant:    %s\n", pol.GetPartiallyCompliantPolicy())
		fmt.Printf("    Unassessed Policy:      %s\n", pol.GetUnassessedPolicy())
		fmt.Printf("    Insufficient Evidence:  %s\n", pol.GetInsufficientEvidencePolicy())
		fmt.Printf("    Require Integrity:      %t\n", pol.GetRequireIntegrity())
	}

	return clierror.ExitSuccess
}

func runGateInspect(args []string) int {
	var filePath string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance gate inspect <policy.json|yaml> [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && filePath == "" {
				filePath = arg
			} else {
				fmt.Fprintf(os.Stderr, "[-] Unknown inspect option: %s\n", arg)
				return clierror.ExitOperational
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: policy file path is required")
		return clierror.ExitOperational
	}

	pol, err := compliance.LoadGatePolicy(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error loading policy %q: %v\n", filePath, err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(pol)
	} else {
		fmt.Println("=== FELIX Compliance Gate Policy ===")
		fmt.Printf("Policy ID:                  %s\n", pol.ID)
		fmt.Printf("Version:                    %s\n", pol.Version)
		if pol.Name != "" {
			fmt.Printf("Name:                       %s\n", pol.Name)
		}
		if pol.Description != "" {
			fmt.Printf("Description:                %s\n", pol.Description)
		}
		if pol.TargetCatalog != "" {
			fmt.Printf("Target Catalog:             %s\n", pol.TargetCatalog)
		}
		fmt.Println("\nPolicy Rules & Enforcement:")
		fmt.Printf("  Max Non-Compliant:        %d\n", pol.GetMaxNonCompliant())
		fmt.Printf("  Max Partially-Compliant:  %d\n", pol.GetMaxPartiallyCompliant())
		fmt.Printf("  Partially-Compliant Mode: %s\n", pol.GetPartiallyCompliantPolicy())
		fmt.Printf("  Unassessed Controls Mode: %s\n", pol.GetUnassessedPolicy())
		fmt.Printf("  Insufficient Evidence:    %s\n", pol.GetInsufficientEvidencePolicy())
		fmt.Printf("  Not Applicable Mode:      %s\n", pol.GetNotApplicablePolicy())
		fmt.Printf("  Min Compliance Rate:      %.2f%%\n", pol.GetMinCompliancePercent())
		fmt.Printf("  Min Assessed Coverage:    %.2f%%\n", pol.GetMinAssessedPercent())
		fmt.Printf("  Require Integrity:        %t\n", pol.GetRequireIntegrity())
		fmt.Printf("  Require HMAC Auth:        %t\n", pol.GetRequireHMAC())
		fmt.Printf("  Strict Integrity Mode:    %t\n", pol.GetStrictIntegrity())
		fmt.Printf("  Fail on Overdue SLA:      %t\n", pol.GetFailOnOverdueSLA())

		if len(pol.EnforcedControls) > 0 {
			fmt.Printf("\nEnforced Controls (%d):\n", len(pol.EnforcedControls))
			for _, c := range pol.EnforcedControls {
				fmt.Printf("  - %s\n", c)
			}
		}
	}

	return clierror.ExitSuccess
}

func runGateCheck(args []string) int {
	var (
		policyPath      string
		assessmentID    string
		catalogID       string
		dossierPath     string
		evaluationPath  string
		dbPath          string
		keyFilePath     string
		keyEnvVar       string
		keyID           string
		strictIntegrity bool
		statusOverride  string
		outputPath      string
		outputFormat    string = "json"
		overwrite       bool
		jsonOutput      bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--policy", "-p":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		case "--assessment", "-a":
			if i+1 < len(args) {
				assessmentID = args[i+1]
				i++
			}
		case "--catalog", "-c":
			if i+1 < len(args) {
				catalogID = args[i+1]
				i++
			}
		case "--dossier-file", "-d":
			if i+1 < len(args) {
				dossierPath = args[i+1]
				i++
			}
		case "--evaluation-file":
			if i+1 < len(args) {
				evaluationPath = args[i+1]
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
		case "--strict-integrity", "--strict":
			strictIntegrity = true
		case "--status":
			if i+1 < len(args) {
				statusOverride = args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				outputFormat = strings.ToLower(args[i+1])
				i++
			}
		case "--overwrite":
			overwrite = true
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printGateHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown gate option: %s\n", arg)
				return clierror.ExitOperational
			}
		}
	}

	// Validation of required arguments
	if strings.TrimSpace(policyPath) == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --policy <file> is required")
		return clierror.ExitOperational
	}

	// Load Gate Policy
	policy, err := compliance.LoadGatePolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error loading gate policy %q: %v\n", policyPath, err)
		return clierror.ExitOperational
	}

	// Resolve KeyProvider
	kp, kpErr := resolveKeyProvider(keyFilePath, keyEnvVar, keyID)
	if kpErr != nil && strictIntegrity {
		fmt.Fprintf(os.Stderr, "[-] Strict integrity mode failed: %v\n", kpErr)
		return clierror.ExitOperational
	}

	gateService := compliance.NewComplianceGateService()
	gateOpts := compliance.GateOptions{
		KeyProvider:      kp,
		StrictIntegrity:  strictIntegrity || policy.GetStrictIntegrity(),
		AssessmentStatus: statusOverride,
		ReportPath:       outputPath,
	}

	var res *compliance.ComplianceGateResult

	// Path 1: Pre-existing ComplianceDossier file
	if dossierPath != "" {
		dossier, err := compliance.LoadDossierFromFile(dossierPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading dossier file %q: %v\n", dossierPath, err)
			return clierror.ExitOperational
		}
		res = gateService.EvaluateDossier(dossier, policy, gateOpts)
	} else if evaluationPath != "" {
		// Path 2: Pre-existing EvaluationResult file
		evalData, err := os.ReadFile(evaluationPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading evaluation file %q: %v\n", evaluationPath, err)
			return clierror.ExitOperational
		}
		var eval compliance.EvaluationResult
		if err := json.Unmarshal(evalData, &eval); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error parsing evaluation file %q: %v\n", evaluationPath, err)
			return clierror.ExitOperational
		}
		res = gateService.EvaluateEvaluationResult(&eval, policy, gateOpts)
	} else {
		// Path 3: Query evaluation from compliance database
		if strings.TrimSpace(assessmentID) == "" {
			fmt.Fprintln(os.Stderr, "[-] Error: --assessment <id> is required (or specify --dossier-file / --evaluation-file)")
			return clierror.ExitOperational
		}

		if dbPath == "" {
			defaultPath, err := compliance.DefaultComplianceDBPath()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error resolving compliance database path: %v\n", err)
				return clierror.ExitOperational
			}
			dbPath = defaultPath
		}

		store, err := compliance.NewSQLiteComplianceStore(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", err)
			return clierror.ExitOperational
		}
		defer store.Close()

		res = gateService.EvaluateFromStore(store, assessmentID, catalogID, policy, gateOpts)
	}

	// Handle secondary output report artifact safely
	if outputPath != "" {
		if err := writeGateReportArtifact(res, outputPath, outputFormat, overwrite); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed writing gate report artifact to %q: %v\n", outputPath, err)
			// Crucial safety guarantee: do not convert an established policy violation to operational failure or pass!
			if res.ExitCode == clierror.ExitSuccess {
				return clierror.ExitOperational
			}
		}
	}

	// Output decision to console
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Print(renderHumanGateReport(res))
	}

	return res.ExitCode
}

func writeGateReportArtifact(res *compliance.ComplianceGateResult, outputPath, format string, overwrite bool) error {
	cleanPath := filepath.Clean(outputPath)

	// Overwrite guard
	if !overwrite {
		if _, err := os.Stat(cleanPath); err == nil {
			return fmt.Errorf("output file %q already exists (use --overwrite to replace)", cleanPath)
		}
	}

	var data []byte
	switch format {
	case "md", "markdown":
		data = []byte(renderMarkdownGateReport(res))
	case "text", "human", "txt":
		data = []byte(renderHumanGateReport(res))
	default: // json
		enc, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		data = enc
	}

	// Atomic write
	tmpPath := fmt.Sprintf("%s.tmp.%d", cleanPath, os.Getpid())
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	if overwrite {
		_ = os.Remove(cleanPath)
	}
	if err := os.Rename(tmpPath, cleanPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	fmt.Fprintf(os.Stderr, "[+] Compliance gate report artifact written to %s\n", cleanPath)
	return nil
}

func renderHumanGateReport(res *compliance.ComplianceGateResult) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                       FELIX COMPLIANCE GATE DECISION                           \n")
	sb.WriteString("================================================================================\n")

	decisionStr := string(res.Decision)
	switch res.Decision {
	case compliance.GateStatusPassed:
		sb.WriteString(fmt.Sprintf("DECISION:  [+] %s (Exit Code: %d)\n", decisionStr, res.ExitCode))
	case compliance.GateStatusPolicyFailed:
		sb.WriteString(fmt.Sprintf("DECISION:  [-] %s (Exit Code: %d)\n", decisionStr, res.ExitCode))
	case compliance.GateStatusOperationalFailed, compliance.GateStatusIndeterminate:
		sb.WriteString(fmt.Sprintf("DECISION:  [!] %s (Exit Code: %d)\n", decisionStr, res.ExitCode))
	}

	sb.WriteString(fmt.Sprintf("Assessment ID:      %s\n", res.AssessmentID))
	if res.ExecutionID != "" {
		sb.WriteString(fmt.Sprintf("Execution ID:       %s\n", res.ExecutionID))
	}
	if res.CatalogIdentity != "" {
		sb.WriteString(fmt.Sprintf("Catalog Identity:   %s\n", res.CatalogIdentity))
	}
	sb.WriteString(fmt.Sprintf("Policy ID:          %s (Version: %s)\n", res.PolicyID, res.PolicyVersion))
	if res.PolicyName != "" {
		sb.WriteString(fmt.Sprintf("Policy Name:        %s\n", res.PolicyName))
	}
	sb.WriteString(fmt.Sprintf("Evaluated At:       %s\n", res.EvaluatedAt.Format("2006-01-02 15:04:05 UTC")))

	sum := res.Summary
	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Evaluation Summary (%d Total Controls):\n", sum.TotalControls))
	sb.WriteString(fmt.Sprintf("  [+] Compliant:             %d\n", sum.CompliantControls))
	sb.WriteString(fmt.Sprintf("  [-] Non-Compliant:         %d\n", sum.NonCompliantControls))
	sb.WriteString(fmt.Sprintf("  [~] Partially Compliant:   %d\n", sum.PartiallyCompliantControls))
	sb.WriteString(fmt.Sprintf("  [?] Insufficient Evidence: %d\n", sum.InsufficientEvidenceControls))
	sb.WriteString(fmt.Sprintf("  [ ] Not Assessed:          %d\n", sum.NotAssessedControls))
	sb.WriteString(fmt.Sprintf("  [*] Not Applicable:        %d\n", sum.NotApplicableControls))
	if sum.ErrorControls > 0 {
		sb.WriteString(fmt.Sprintf("  [!] Error Controls:        %d\n", sum.ErrorControls))
	}
	sb.WriteString(fmt.Sprintf("  Compliance Rate:           %.2f%%\n", sum.CompliancePercent))
	sb.WriteString(fmt.Sprintf("  Assessment Coverage:       %.2f%%\n", sum.AssessedPercent))
	if sum.OverdueSLACount > 0 {
		sb.WriteString(fmt.Sprintf("  Overdue SLA Items:         %d\n", sum.OverdueSLACount))
	}

	if len(res.Violations) > 0 {
		sb.WriteString("\n--------------------------------------------------------------------------------\n")
		sb.WriteString(fmt.Sprintf("Policy Violations (%d):\n", len(res.Violations)))
		for i, v := range res.Violations {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, v))
		}
	}

	if len(res.OperationalErrors) > 0 {
		sb.WriteString("\n--------------------------------------------------------------------------------\n")
		sb.WriteString(fmt.Sprintf("Operational & Integrity Errors (%d):\n", len(res.OperationalErrors)))
		for i, e := range res.OperationalErrors {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, e))
		}
	}

	if len(res.IndeterminateReasons) > 0 {
		sb.WriteString("\n--------------------------------------------------------------------------------\n")
		sb.WriteString(fmt.Sprintf("Indeterminate Conditions (%d):\n", len(res.IndeterminateReasons)))
		for i, r := range res.IndeterminateReasons {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, r))
		}
	}

	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Enforced Conditions Breakdown (%d Total: %d Passed, %d Failed, %d Indeterminate):\n",
		sum.TotalConditions, sum.PassedConditions, sum.FailedConditions, sum.IndeterminateConditions))
	for _, c := range res.Conditions {
		marker := "[+]"
		if c.Status == "FAILED" {
			marker = "[-]"
		} else if c.Status == "INDETERMINATE" {
			marker = "[?]"
		}
		sb.WriteString(fmt.Sprintf("  %s %-36s : %s\n", marker, c.Name, c.Message))
	}

	sb.WriteString("\nLimitations Notice:\n")
	sb.WriteString(fmt.Sprintf("  %s\n", res.LimitationsNotice))
	sb.WriteString("================================================================================\n")
	return sb.String()
}

func renderMarkdownGateReport(res *compliance.ComplianceGateResult) string {
	var sb strings.Builder
	sb.WriteString("# FELIX Compliance Gate Decision Report\n\n")

	badge := "🟢 **PASS**"
	if res.Decision == compliance.GateStatusPolicyFailed {
		badge = "🔴 **POLICY FAILURE**"
	} else if res.Decision == compliance.GateStatusOperationalFailed || res.Decision == compliance.GateStatusIndeterminate {
		badge = "⚠️ **OPERATIONAL FAILURE / INDETERMINATE**"
	}

	sb.WriteString(fmt.Sprintf("### Decision: %s (Exit Code: `%d`)\n\n", badge, res.ExitCode))
	sb.WriteString(fmt.Sprintf("- **Assessment ID:** `%s`\n", res.AssessmentID))
	sb.WriteString(fmt.Sprintf("- **Catalog Identity:** `%s`\n", res.CatalogIdentity))
	sb.WriteString(fmt.Sprintf("- **Policy:** `%s` (Version: `%s`)\n", res.PolicyID, res.PolicyVersion))
	sb.WriteString(fmt.Sprintf("- **Evaluated At:** `%s`\n\n", res.EvaluatedAt.Format("2006-01-02 15:04:05 UTC")))

	sb.WriteString("## Evaluation Summary\n\n")
	sb.WriteString("| Metric | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Total Controls | %d |\n", res.Summary.TotalControls))
	sb.WriteString(fmt.Sprintf("| Compliant Controls | %d |\n", res.Summary.CompliantControls))
	sb.WriteString(fmt.Sprintf("| Non-Compliant Controls | %d |\n", res.Summary.NonCompliantControls))
	sb.WriteString(fmt.Sprintf("| Partially Compliant Controls | %d |\n", res.Summary.PartiallyCompliantControls))
	sb.WriteString(fmt.Sprintf("| Insufficient Evidence | %d |\n", res.Summary.InsufficientEvidenceControls))
	sb.WriteString(fmt.Sprintf("| Not Assessed | %d |\n", res.Summary.NotAssessedControls))
	sb.WriteString(fmt.Sprintf("| Compliance Rate | %.2f%% |\n", res.Summary.CompliancePercent))
	sb.WriteString(fmt.Sprintf("| Assessed Coverage | %.2f%% |\n\n", res.Summary.AssessedPercent))

	if len(res.Violations) > 0 {
		sb.WriteString("## Policy Violations\n\n")
		for _, v := range res.Violations {
			sb.WriteString(fmt.Sprintf("- ❌ %s\n", v))
		}
		sb.WriteString("\n")
	}

	if len(res.OperationalErrors) > 0 {
		sb.WriteString("## Operational & Integrity Errors\n\n")
		for _, e := range res.OperationalErrors {
			sb.WriteString(fmt.Sprintf("- ⚠️ %s\n", e))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Enforced Policy Conditions\n\n")
	sb.WriteString("| Status | Condition | Details |\n|---|---|---|\n")
	for _, c := range res.Conditions {
		icon := "✅"
		if c.Status == "FAILED" {
			icon = "❌"
		} else if c.Status == "INDETERMINATE" {
			icon = "⚠️"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", icon, c.Name, c.Message))
	}
	sb.WriteString("\n")

	sb.WriteString("> **Notice:** " + res.LimitationsNotice + "\n")
	return sb.String()
}
