package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runComplianceDossier(args []string) int {
	if len(args) == 0 {
		printDossierHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "generate", "gen":
		return runDossierGenerate(subArgs)
	case "validate", "check":
		return runDossierValidate(subArgs)
	case "view", "show":
		return runDossierView(subArgs)
	case "help", "--help", "-h":
		printDossierHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown dossier subcommand: %s\n\n", sub)
		printDossierHelp()
		return clierror.ExitOperational
	}
}

func printDossierHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance dossier <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  generate     Generate an evidence-backed compliance dossier snapshot")
	fmt.Println("  validate     Validate a compliance dossier file for schema and semantic consistency")
	fmt.Println("  view         Display a human-readable summary of a compliance dossier file")
	fmt.Println("  help         Display this help message")
	fmt.Println("\nOptions for 'generate':")
	fmt.Println("  --assessment <id>, -a <id>   Assessment ID (required)")
	fmt.Println("  --catalog <id>, -c <id>      Catalog ID (required, e.g. nist-sp-800-53:5.1.0)")
	fmt.Println("  --catalog-file <path>        Path to local ControlCatalog JSON file")
	fmt.Println("  --output <path>, -o <path>   Output file path (default: stdout)")
	fmt.Println("  --overwrite                  Allow overwriting an existing output file")
	fmt.Println("  --strict-integrity, --strict Fail closed if any source record fails integrity check")
	fmt.Println("  --include-remediation        Include remediation records in the dossier")
	fmt.Println("  --include-sla                Include remediation SLA metrics in the dossier")
	fmt.Println("  --include-mttr               Include MTTR calculations in the dossier")
	fmt.Println("  --format <json|human>        Output format (default: json)")
	fmt.Println("  --key-file <path>            Path to file containing HMAC verification key")
	fmt.Println("  --key-env <var>              Environment variable containing verification key")
	fmt.Println("  --key <path>                 Alias for --key-file")
	fmt.Println("  --key-id <id>                Identifier for verification key")
	fmt.Println("  --db <path>                  Custom compliance database path")
	fmt.Println("  --help, -h                   Show help")
}

func runDossierGenerate(args []string) int {
	var (
		assessmentID       string
		catalogID          string
		catalogFilePath    string
		mappingID          string
		mappingFilePath    string
		outputPath         string
		overwrite          bool
		strictIntegrity    bool
		includeRemediation bool
		includeSLA         bool
		includeMTTR        bool
		format             = "json"
		keyFilePath        string
		keyEnvVar          string
		keyID              string
		dbPath             string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
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
		case "--catalog-file":
			if i+1 < len(args) {
				catalogFilePath = args[i+1]
				i++
			}
		case "--mapping", "-m":
			if i+1 < len(args) {
				mappingID = args[i+1]
				i++
			}
		case "--mapping-file", "--ruleset":
			if i+1 < len(args) {
				mappingFilePath = args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case "--overwrite":
			overwrite = true
		case "--strict-integrity", "--strict":
			strictIntegrity = true
		case "--include-remediation":
			includeRemediation = true
		case "--include-sla":
			includeSLA = true
		case "--include-mttr":
			includeMTTR = true
		case "--format":
			if i+1 < len(args) {
				format = strings.ToLower(strings.TrimSpace(args[i+1]))
				i++
			}
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
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--help", "-h":
			printDossierHelp()
			return clierror.ExitSuccess
		default:
			fmt.Fprintf(os.Stderr, "[-] Unknown generate option: %s\n", args[i])
			return clierror.ExitOperational
		}
	}

	if strings.TrimSpace(assessmentID) == "" {
		fmt.Fprintln(os.Stderr, "[-] Missing required option: --assessment <id>")
		return clierror.ExitOperational
	}
	if strings.TrimSpace(catalogID) == "" && strings.TrimSpace(catalogFilePath) == "" {
		fmt.Fprintln(os.Stderr, "[-] Missing required option: --catalog <id> or --catalog-file <path>")
		return clierror.ExitOperational
	}

	// Overwrite guard: check if output file exists
	if outputPath != "" && !overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			fmt.Fprintf(os.Stderr, "[-] Output file %q already exists; specify --overwrite to replace it\n", outputPath)
			return clierror.ExitOperational
		}
	}

	// Resolve database path
	if dbPath == "" {
		defaultPath, err := compliance.DefaultComplianceDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default compliance database path: %v\n", err)
			return clierror.ExitOperational
		}
		dbPath = defaultPath
	}

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed opening compliance store at %s: %v\n", dbPath, err)
		return clierror.ExitOperational
	}
	defer store.Close()

	// Resolve optional KeyProvider
	var kp compliance.KeyProvider
	if keyFilePath != "" {
		if keyID == "" {
			keyID = filepath.Base(keyFilePath)
		}
		fileProvider := compliance.NewFileKeyProvider(keyFilePath, keyID)
		if _, err := fileProvider.GetVerificationKey(context.Background(), keyID); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid key configuration: %v\n", err)
			return clierror.ExitOperational
		}
		kp = fileProvider
	} else if keyEnvVar != "" {
		kp = compliance.NewEnvKeyProvider(keyEnvVar)
	} else if os.Getenv("FELIX_COMPLIANCE_SIGNING_KEY") != "" || os.Getenv("FELIX_COMPLIANCE_KEY") != "" {
		kp = compliance.NewEnvKeyProvider("FELIX_COMPLIANCE_SIGNING_KEY")
	}

	svc := compliance.NewDossierService(store, nil)

	req := compliance.GenerateDossierRequest{
		AssessmentID:       assessmentID,
		CatalogID:          catalogID,
		CatalogPath:        catalogFilePath,
		MappingRuleSetID:   mappingID,
		MappingPath:        mappingFilePath,
		IncludeRemediation: includeRemediation,
		IncludeSLA:         includeSLA,
		IncludeMTTR:        includeMTTR,
		StrictIntegrity:    strictIntegrity,
		KeyProvider:        kp,
	}

	dossier, err := svc.GenerateDossier(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed generating compliance dossier: %v\n", err)
		return clierror.ExitOperational
	}

	// Serialize output
	var outBytes []byte
	if format == "human" {
		outBytes = []byte(renderHumanDossier(dossier))
	} else {
		pretty, err := dossier.ToPrettyJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed formatting dossier JSON: %v\n", err)
			return clierror.ExitOperational
		}
		outBytes = pretty
	}

	// Write output atomically if writing to file
	if outputPath != "" {
		tmpPath := fmt.Sprintf("%s.tmp.%d", outputPath, os.Getpid())
		if err := os.WriteFile(tmpPath, outBytes, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed writing temporary dossier file: %v\n", err)
			return clierror.ExitOperational
		}
		if overwrite {
			_ = os.Remove(outputPath)
		}
		if err := os.Rename(tmpPath, outputPath); err != nil {
			_ = os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "[-] Failed moving temporary file to destination %s: %v\n", outputPath, err)
			return clierror.ExitOperational
		}
		fmt.Fprintf(os.Stderr, "[+] Compliance dossier written to %s (logical digest: %s)\n", outputPath, dossier.LogicalDigest)
	} else {
		// Machine-readable stdout
		_, _ = os.Stdout.Write(outBytes)
		if !strings.HasSuffix(string(outBytes), "\n") {
			_, _ = os.Stdout.Write([]byte("\n"))
		}
	}

	// Return ExitSecurityFail (1) if assessment completed with non-compliant controls
	if dossier.Summary.NonCompliantCount > 0 {
		return clierror.ExitSecurityFail
	}

	return clierror.ExitSuccess
}

func runDossierValidate(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: felix compliance dossier validate <file.json>")
		return clierror.ExitOperational
	}

	filePath := args[0]
	dossier, err := compliance.LoadDossierFromFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dossier validation FAILED for %s: %v\n", filePath, err)
		return clierror.ExitOperational
	}

	fmt.Fprintf(os.Stdout, "[+] Dossier %s is VALID (schema: %s, digest: %s, controls: %d)\n",
		dossier.Identity.DossierID, dossier.Identity.SchemaVersion, dossier.LogicalDigest, len(dossier.Controls))
	return clierror.ExitSuccess
}

func runDossierView(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: felix compliance dossier view <file.json>")
		return clierror.ExitOperational
	}

	filePath := args[0]
	dossier, err := compliance.LoadDossierFromFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed reading dossier file %s: %v\n", filePath, err)
		return clierror.ExitOperational
	}

	fmt.Print(renderHumanDossier(dossier))
	return clierror.ExitSuccess
}

func renderHumanDossier(d *compliance.ComplianceDossier) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("FELIX COMPLIANCE DOSSIER — %s\n", d.Identity.DossierID))
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Schema Version     : %s\n", d.Identity.SchemaVersion))
	sb.WriteString(fmt.Sprintf("Assessment ID      : %s\n", d.Identity.AssessmentID))
	sb.WriteString(fmt.Sprintf("Execution ID       : %s\n", d.Identity.ExecutionID))
	sb.WriteString(fmt.Sprintf("Catalog Identity   : %s\n", d.Identity.CatalogID))
	sb.WriteString(fmt.Sprintf("Generated At (UTC) : %s\n", d.Identity.GeneratedAt.UTC().Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("Completeness Status: %s\n", d.Identity.CompletenessStatus))
	sb.WriteString(fmt.Sprintf("Logical Digest     : %s\n\n", d.LogicalDigest))

	sb.WriteString("--- ASSESSMENT SUMMARY ---\n")
	sb.WriteString(fmt.Sprintf("Overall Status    : %s\n", d.Summary.OverallStatus))
	sb.WriteString(fmt.Sprintf("Total Controls    : %d\n", d.Summary.TotalControls))
	sb.WriteString(fmt.Sprintf("Compliant         : %d\n", d.Summary.CompliantCount))
	sb.WriteString(fmt.Sprintf("Non-Compliant     : %d\n", d.Summary.NonCompliantCount))
	sb.WriteString(fmt.Sprintf("Partially Compliant: %d\n", d.Summary.PartiallyCompliantCount))
	sb.WriteString(fmt.Sprintf("Not Assessed      : %d\n", d.Summary.NotAssessedCount))
	sb.WriteString(fmt.Sprintf("Insufficient Evid : %d\n", d.Summary.InsufficientEvidenceCount))
	sb.WriteString(fmt.Sprintf("Not Applicable    : %d\n", d.Summary.NotApplicableCount))
	sb.WriteString(fmt.Sprintf("Errors            : %d\n", d.Summary.ErrorCount))
	sb.WriteString(fmt.Sprintf("Total Findings    : %d (Mapped: %d, Unmapped: %d)\n",
		d.Summary.TotalFindings, d.Summary.MappedFindings, d.Summary.UnmappedFindings))
	sb.WriteString(fmt.Sprintf("Evidence Links    : %d (Verified: %d, Unverified: %d)\n",
		d.Summary.TotalEvidenceLinks, d.Summary.VerifiedEvidenceCount, d.Summary.UnverifiedEvidenceCount))

	if d.CoverageBasis != nil {
		sb.WriteString(fmt.Sprintf("Assessed Coverage : %d / %d applicable controls (%.1f%%)\n", d.CoverageBasis.AssessedControls, d.CoverageBasis.ApplicableControls, d.CoverageBasis.AssessedCoveragePercent))
		sb.WriteString(fmt.Sprintf("Compliance Rate   : %d / %d applicable controls (%.1f%%)\n\n", d.CoverageBasis.CompliantControls, d.CoverageBasis.ApplicableControls, d.CoverageBasis.ComplianceRatePercent))
	} else {
		sb.WriteString("\n")
	}

	if d.Summary.MTTRSummary != nil && d.Summary.MTTRSummary.HasData {
		sb.WriteString("--- MTTR & SLA PERFORMANCE ---\n")
		sb.WriteString(fmt.Sprintf("Mean Time to Remediation : %s\n", d.Summary.MTTRSummary.MTTRString))
		sb.WriteString(fmt.Sprintf("Completed Episodes       : %d\n", d.Summary.MTTRSummary.CompletedEpisodes))
		sb.WriteString(fmt.Sprintf("Total Duration           : %s\n", d.Summary.MTTRSummary.TotalDurationString))
		sb.WriteString(fmt.Sprintf("MTTR Coverage Status     : %s\n\n", d.Summary.MTTRSummary.CoverageStatus))
	}

	sb.WriteString("--- CONTROL EVALUATION DETAILS ---\n")
	for _, c := range d.Controls {
		sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", strings.ToUpper(string(c.EvaluationState)), c.ControlID, c.ControlTitle))
		sb.WriteString(fmt.Sprintf("  Rationale : %s\n", c.Rationale))
		if len(c.MappedFindings) > 0 {
			fids := make([]string, len(c.MappedFindings))
			for i, mf := range c.MappedFindings {
				fids[i] = fmt.Sprintf("%s (%s)", mf.FindingID, mf.Relationship)
			}
			sb.WriteString(fmt.Sprintf("  Findings  : %s\n", strings.Join(fids, ", ")))
		}
		if len(c.SupportingEvidence) > 0 {
			sb.WriteString(fmt.Sprintf("  Supporting Evidence   : %s\n", strings.Join(c.SupportingEvidence, "; ")))
		}
		if len(c.ContradictingEvidence) > 0 {
			sb.WriteString(fmt.Sprintf("  Violating Evidence    : %s\n", strings.Join(c.ContradictingEvidence, "; ")))
		}
		if c.Remediation != nil {
			sb.WriteString(fmt.Sprintf("  Remediation Status    : %s (Overdue: %v)\n", c.Remediation.Status, c.Remediation.IsOverdue))
		}
	}

	sb.WriteString("\n--- INTEGRITY & LIMITATIONS ---\n")
	sb.WriteString(fmt.Sprintf("Evaluation Integrity Status : %s\n", d.Integrity.EvaluationIntegrityStatus))
	if len(d.Integrity.IntegrityFailures) > 0 {
		sb.WriteString(fmt.Sprintf("Integrity Failures          : %s\n", strings.Join(d.Integrity.IntegrityFailures, "; ")))
	}
	if len(d.Summary.Limitations) > 0 {
		sb.WriteString("Limitations & Notes         :\n")
		for _, lim := range d.Summary.Limitations {
			sb.WriteString(fmt.Sprintf("  - %s\n", lim))
		}
	}
	sb.WriteString(fmt.Sprintf("Notice                      : %s\n", d.Integrity.LimitationsNotice))
	sb.WriteString("================================================================================\n")
	return sb.String()
}
