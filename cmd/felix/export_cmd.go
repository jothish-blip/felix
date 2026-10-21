package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runComplianceExport(args []string) int {
	if len(args) == 0 {
		printExportHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "json":
		return runExportJSON(subArgs)
	case "oscal":
		return runExportOSCAL(subArgs)
	case "validate", "check":
		return runExportValidate(subArgs)
	case "help", "--help", "-h":
		printExportHelp()
		return clierror.ExitSuccess
	default:
		// If first argument starts with dash, check if user provided options directly
		if strings.HasPrefix(sub, "-") {
			fmt.Fprintf(os.Stderr, "[-] Missing export subcommand ('json', 'oscal', or 'validate')\n\n")
		} else {
			fmt.Fprintf(os.Stderr, "[-] Unknown export subcommand: %s\n\n", sub)
		}
		printExportHelp()
		return clierror.ExitOperational
	}
}

func printExportHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance export <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  json         Export compliance evaluation records in normalized JSON format")
	fmt.Println("  oscal        Export compliance records in NIST OSCAL v1.1.0 format (Assessment Results or POA&M)")
	fmt.Println("  validate     Validate an exported compliance artifact (auto-detects format)")
	fmt.Println("  help         Display this help message")
	fmt.Println("\nOptions for 'json' and 'oscal':")
	fmt.Println("  --assessment <id>, -a <id>   Assessment ID (required unless --dossier-file is provided)")
	fmt.Println("  --catalog <id>, -c <id>      Catalog ID (required unless --dossier-file is provided)")
	fmt.Println("  --catalog-file <path>        Path to local ControlCatalog JSON file")
	fmt.Println("  --mapping <id>, -m <id>      Mapping ruleset ID")
	fmt.Println("  --mapping-file <path>        Path to mapping ruleset JSON file")
	fmt.Println("  --dossier-file <path>, -d    Pre-existing ComplianceDossier JSON file to export from")
	fmt.Println("  --output <path>, -o <path>   Output file path (default: stdout)")
	fmt.Println("  --overwrite                  Allow overwriting an existing output file")
	fmt.Println("  --strict-integrity, --strict Fail closed if any source record fails integrity check")
	fmt.Println("  --include-remediation        Include remediation records in the export")
	fmt.Println("  --include-sla                Include remediation SLA metrics")
	fmt.Println("  --include-mttr               Include MTTR calculations")
	fmt.Println("  --oscal-model <ar|poam>      OSCAL model to export: 'ar' (Assessment Results, default) or 'poam'")
	fmt.Println("  --compact                    Output compact JSON instead of formatted JSON")
	fmt.Println("  --key-file <path>            Path to file containing HMAC verification key")
	fmt.Println("  --key-env <var>              Environment variable containing verification key")
	fmt.Println("  --key <path>                 Alias for --key-file")
	fmt.Println("  --key-id <id>                Identifier for verification key")
	fmt.Println("  --db <path>                  Custom compliance database path")
	fmt.Println("  --help, -h                   Show help")
	fmt.Println("\nOptions for 'validate':")
	fmt.Println("  <file.json>                  Path to compliance export file to validate")
	fmt.Println("  --json                       Output machine-readable validation report JSON")
	fmt.Println("  --help, -h                   Show help")
}

type exportCLIOptions struct {
	assessmentID       string
	catalogID          string
	catalogFilePath    string
	mappingID          string
	mappingFilePath    string
	dossierFilePath    string
	outputPath         string
	overwrite          bool
	strictIntegrity    bool
	includeRemediation bool
	includeSLA         bool
	includeMTTR        bool
	oscalModel         string
	compact            bool
	keyFilePath        string
	keyEnvVar          string
	keyID              string
	dbPath             string
}

func parseExportCLIOptions(args []string) (*exportCLIOptions, bool, int) {
	opts := &exportCLIOptions{
		oscalModel: "ar",
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--assessment", "-a":
			if i+1 < len(args) {
				opts.assessmentID = args[i+1]
				i++
			}
		case "--catalog", "-c":
			if i+1 < len(args) {
				opts.catalogID = args[i+1]
				i++
			}
		case "--catalog-file":
			if i+1 < len(args) {
				opts.catalogFilePath = args[i+1]
				i++
			}
		case "--mapping", "-m":
			if i+1 < len(args) {
				opts.mappingID = args[i+1]
				i++
			}
		case "--mapping-file", "--ruleset":
			if i+1 < len(args) {
				opts.mappingFilePath = args[i+1]
				i++
			}
		case "--dossier-file", "-d":
			if i+1 < len(args) {
				opts.dossierFilePath = args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				opts.outputPath = args[i+1]
				i++
			}
		case "--overwrite":
			opts.overwrite = true
		case "--strict-integrity", "--strict":
			opts.strictIntegrity = true
		case "--include-remediation":
			opts.includeRemediation = true
		case "--include-sla":
			opts.includeSLA = true
		case "--include-mttr":
			opts.includeMTTR = true
		case "--oscal-model":
			if i+1 < len(args) {
				opts.oscalModel = strings.ToLower(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--compact":
			opts.compact = true
		case "--key-file", "--key":
			if i+1 < len(args) {
				opts.keyFilePath = args[i+1]
				i++
			}
		case "--key-env":
			if i+1 < len(args) {
				opts.keyEnvVar = args[i+1]
				i++
			}
		case "--key-id":
			if i+1 < len(args) {
				opts.keyID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				opts.dbPath = args[i+1]
				i++
			}
		case "--help", "-h":
			printExportHelp()
			return nil, false, clierror.ExitSuccess
		default:
			fmt.Fprintf(os.Stderr, "[-] Unknown export option: %s\n", args[i])
			return nil, false, clierror.ExitOperational
		}
	}

	return opts, true, clierror.ExitSuccess
}

func resolveKeyProviderForExport(opts *exportCLIOptions) (compliance.KeyProvider, error) {
	if opts.keyFilePath != "" {
		keyID := opts.keyID
		if keyID == "" {
			keyID = filepath.Base(opts.keyFilePath)
		}
		fileProvider := compliance.NewFileKeyProvider(opts.keyFilePath, keyID)
		if _, err := fileProvider.GetVerificationKey(context.Background(), keyID); err != nil {
			return nil, fmt.Errorf("invalid key configuration: %w", err)
		}
		return fileProvider, nil
	} else if opts.keyEnvVar != "" {
		return compliance.NewEnvKeyProvider(opts.keyEnvVar), nil
	} else if os.Getenv("FELIX_COMPLIANCE_SIGNING_KEY") != "" || os.Getenv("FELIX_COMPLIANCE_KEY") != "" {
		return compliance.NewEnvKeyProvider("FELIX_COMPLIANCE_SIGNING_KEY"), nil
	}
	return nil, nil
}

func writeExportOutput(outputPath string, overwrite bool, data []byte, logPrefix string) int {
	if outputPath != "" {
		if !overwrite {
			if _, err := os.Stat(outputPath); err == nil {
				fmt.Fprintf(os.Stderr, "[-] Output file %q already exists; specify --overwrite to replace it\n", outputPath)
				return clierror.ExitOperational
			}
		}

		tmpPath := fmt.Sprintf("%s.tmp.%d", outputPath, os.Getpid())
		if err := os.WriteFile(tmpPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed writing temporary export file: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "[+] %s written to %s\n", logPrefix, outputPath)
	} else {
		// Output clean machine-readable payload to stdout
		_, _ = os.Stdout.Write(data)
		if !strings.HasSuffix(string(data), "\n") {
			_, _ = os.Stdout.Write([]byte("\n"))
		}
	}
	return clierror.ExitSuccess
}

func runExportJSON(args []string) int {
	opts, ok, code := parseExportCLIOptions(args)
	if !ok {
		return code
	}

	var sourceDossier *compliance.ComplianceDossier
	if opts.dossierFilePath != "" {
		d, err := compliance.LoadDossierFromFile(opts.dossierFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed loading source dossier file %s: %v\n", opts.dossierFilePath, err)
			return clierror.ExitOperational
		}
		sourceDossier = d
	} else {
		if strings.TrimSpace(opts.assessmentID) == "" {
			fmt.Fprintln(os.Stderr, "[-] Missing required option: --assessment <id> (or specify --dossier-file <path>)")
			return clierror.ExitOperational
		}
		if strings.TrimSpace(opts.catalogID) == "" && strings.TrimSpace(opts.catalogFilePath) == "" {
			fmt.Fprintln(os.Stderr, "[-] Missing required option: --catalog <id> or --catalog-file <path>")
			return clierror.ExitOperational
		}
	}

	// Resolve database path
	dbPath := opts.dbPath
	if dbPath == "" && sourceDossier == nil {
		defaultPath, err := compliance.DefaultComplianceDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default compliance database path: %v\n", err)
			return clierror.ExitOperational
		}
		dbPath = defaultPath
	}

	var store compliance.ComplianceStore
	if sourceDossier == nil {
		s, err := compliance.NewSQLiteComplianceStore(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed opening compliance store at %s: %v\n", dbPath, err)
			return clierror.ExitOperational
		}
		defer s.Close()
		store = s
	}

	kp, err := resolveKeyProviderForExport(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return clierror.ExitOperational
	}

	svc := compliance.NewExportService(store, nil)
	req := compliance.ExportRequest{
		AssessmentID:       opts.assessmentID,
		CatalogID:          opts.catalogID,
		CatalogPath:        opts.catalogFilePath,
		MappingRuleSetID:   opts.mappingID,
		MappingPath:        opts.mappingFilePath,
		Dossier:            sourceDossier,
		Format:             compliance.ExportFormatNormalizedJSON,
		IncludeRemediation: opts.includeRemediation,
		IncludeSLA:         opts.includeSLA,
		IncludeMTTR:        opts.includeMTTR,
		StrictIntegrity:    opts.strictIntegrity,
		KeyProvider:        kp,
	}

	exp, err := svc.GenerateNormalizedExport(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Normalized JSON export failed: %v\n", err)
		return clierror.ExitOperational
	}

	var outBytes []byte
	if opts.compact {
		outBytes, err = exp.ToJSON()
	} else {
		outBytes, err = exp.ToPrettyJSON()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed serializing normalized export JSON: %v\n", err)
		return clierror.ExitOperational
	}

	if writeCode := writeExportOutput(opts.outputPath, opts.overwrite, outBytes, fmt.Sprintf("Normalized compliance export (digest: %s)", exp.LogicalDigest)); writeCode != clierror.ExitSuccess {
		return writeCode
	}

	// Exit 1 if non-compliant controls exist; Exit 0 if clean
	if exp.Summary.NonCompliantCount > 0 {
		return clierror.ExitSecurityFail
	}
	return clierror.ExitSuccess
}

func runExportOSCAL(args []string) int {
	opts, ok, code := parseExportCLIOptions(args)
	if !ok {
		return code
	}

	var sourceDossier *compliance.ComplianceDossier
	if opts.dossierFilePath != "" {
		d, err := compliance.LoadDossierFromFile(opts.dossierFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed loading source dossier file %s: %v\n", opts.dossierFilePath, err)
			return clierror.ExitOperational
		}
		sourceDossier = d
	} else {
		if strings.TrimSpace(opts.assessmentID) == "" {
			fmt.Fprintln(os.Stderr, "[-] Missing required option: --assessment <id> (or specify --dossier-file <path>)")
			return clierror.ExitOperational
		}
		if strings.TrimSpace(opts.catalogID) == "" && strings.TrimSpace(opts.catalogFilePath) == "" {
			fmt.Fprintln(os.Stderr, "[-] Missing required option: --catalog <id> or --catalog-file <path>")
			return clierror.ExitOperational
		}
	}

	// Resolve database path
	dbPath := opts.dbPath
	if dbPath == "" && sourceDossier == nil {
		defaultPath, err := compliance.DefaultComplianceDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default compliance database path: %v\n", err)
			return clierror.ExitOperational
		}
		dbPath = defaultPath
	}

	var store compliance.ComplianceStore
	if sourceDossier == nil {
		s, err := compliance.NewSQLiteComplianceStore(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed opening compliance store at %s: %v\n", dbPath, err)
			return clierror.ExitOperational
		}
		defer s.Close()
		store = s
	}

	kp, err := resolveKeyProviderForExport(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return clierror.ExitOperational
	}

	svc := compliance.NewExportService(store, nil)
	req := compliance.ExportRequest{
		AssessmentID:       opts.assessmentID,
		CatalogID:          opts.catalogID,
		CatalogPath:        opts.catalogFilePath,
		MappingRuleSetID:   opts.mappingID,
		MappingPath:        opts.mappingFilePath,
		Dossier:            sourceDossier,
		IncludeRemediation: opts.includeRemediation,
		IncludeSLA:         opts.includeSLA,
		IncludeMTTR:        opts.includeMTTR,
		StrictIntegrity:    opts.strictIntegrity,
		KeyProvider:        kp,
	}

	modelType := strings.ToLower(opts.oscalModel)
	var outBytes []byte
	var hasNonCompliant bool

	switch modelType {
	case "ar", "assessment-results", "assessment_results":
		req.Format = compliance.ExportFormatOSCALAssessmentResults
		doc, err := svc.GenerateOSCALAssessmentResults(context.Background(), req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] OSCAL Assessment Results export failed: %v\n", err)
			return clierror.ExitOperational
		}

		if opts.compact {
			outBytes, err = doc.ToJSON()
		} else {
			outBytes, err = doc.ToPrettyJSON()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed serializing OSCAL Assessment Results: %v\n", err)
			return clierror.ExitOperational
		}

		// Check if any finding exists
		for _, res := range doc.AssessmentResults.Results {
			if len(res.Findings) > 0 {
				hasNonCompliant = true
				break
			}
		}

		if writeCode := writeExportOutput(opts.outputPath, opts.overwrite, outBytes, fmt.Sprintf("OSCAL v%s Assessment Results (UUID: %s)", doc.AssessmentResults.Metadata.OSCALVersion, doc.AssessmentResults.UUID)); writeCode != clierror.ExitSuccess {
			return writeCode
		}

	case "poam", "plan-of-action-and-milestones", "plan_of_action_and_milestones":
		req.Format = compliance.ExportFormatOSCALPOAM
		doc, err := svc.GenerateOSCALPOAM(context.Background(), req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] OSCAL POA&M export failed: %v\n", err)
			return clierror.ExitOperational
		}

		if opts.compact {
			outBytes, err = doc.ToJSON()
		} else {
			outBytes, err = doc.ToPrettyJSON()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed serializing OSCAL POA&M: %v\n", err)
			return clierror.ExitOperational
		}

		// Check if any open POAM items exist
		for _, item := range doc.PlanOfActionAndMilestones.POAMItems {
			for _, prop := range item.Props {
				if prop.Name == "status" && prop.Value != "remediated" {
					hasNonCompliant = true
					break
				}
			}
			if hasNonCompliant {
				break
			}
		}

		if writeCode := writeExportOutput(opts.outputPath, opts.overwrite, outBytes, fmt.Sprintf("OSCAL v%s POA&M (UUID: %s)", doc.PlanOfActionAndMilestones.Metadata.OSCALVersion, doc.PlanOfActionAndMilestones.UUID)); writeCode != clierror.ExitSuccess {
			return writeCode
		}

	default:
		fmt.Fprintf(os.Stderr, "[-] Unsupported --oscal-model %q: must be 'ar' (Assessment Results) or 'poam' (POA&M)\n", opts.oscalModel)
		return clierror.ExitOperational
	}

	if hasNonCompliant {
		return clierror.ExitSecurityFail
	}
	return clierror.ExitSuccess
}

func runExportValidate(args []string) int {
	var filePath string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance export validate <file.json> [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(args[i], "-") && filePath == "" {
				filePath = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "[-] Unknown validate option: %s\n", args[i])
				return clierror.ExitOperational
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Missing required argument: <file.json>")
		fmt.Fprintln(os.Stderr, "Usage: felix compliance export validate <file.json> [--json]")
		return clierror.ExitOperational
	}

	rep, err := compliance.ValidateExportFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening export file %s: %v\n", filePath, err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc, _ := json.MarshalIndent(rep, "", "  ")
		_, _ = os.Stdout.Write(enc)
		_, _ = os.Stdout.Write([]byte("\n"))
		if rep.HasErrors() {
			return clierror.ExitOperational
		}
		return clierror.ExitSuccess
	}

	if rep.HasErrors() {
		fmt.Fprintf(os.Stderr, "[-] Compliance export validation FAILED for %s (format: %s)\n", filePath, rep.DetectedFormat)
		for _, e := range rep.Errors {
			fmt.Fprintf(os.Stderr, "    - %s\n", e)
		}
		return clierror.ExitOperational
	}

	fmt.Fprintf(os.Stdout, "[+] Compliance export %s is VALID (format: %s)\n", filePath, rep.DetectedFormat)
	for k, v := range rep.Summary {
		fmt.Fprintf(os.Stdout, "    %s: %v\n", k, v)
	}
	return clierror.ExitSuccess
}
