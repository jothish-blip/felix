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

func runComplianceLimitations(args []string) int {
	if len(args) == 0 {
		printLimitationsHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "inspect", "show", "view":
		return runLimitationsInspect(subArgs)
	case "list", "ls":
		return runLimitationsList(subArgs)
	case "check", "validate":
		return runLimitationsCheck(subArgs)
	case "boundaries", "determination":
		return runLimitationsBoundaries(subArgs)
	case "help", "--help", "-h":
		printLimitationsHelp()
		return clierror.ExitSuccess
	default:
		if strings.HasPrefix(sub, "-") {
			return runLimitationsInspect(args)
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown limitations command: %s\n\n", sub)
		printLimitationsHelp()
		return clierror.ExitOperational
	}
}

func printLimitationsHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance limitations <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  inspect [options]           Inspect assessment coverage basis, limitations, and determination boundaries")
	fmt.Println("  list [options]              List all identified limitations for an assessment or dossier")
	fmt.Println("  check [options]             Validate an evaluation or dossier for false-compliance contradictions")
	fmt.Println("  boundaries                  Display statutory and technical determination boundary declarations")
	fmt.Println("  help                        Display this help message")
	fmt.Println("\nOptions:")
	fmt.Println("  --assessment <id>, -a       Assessment ID to inspect")
	fmt.Println("  --catalog <id>, -c          Catalog ID or identity (e.g. nist-sp800-53-sample)")
	fmt.Println("  --dossier-file <path>, -d   Path to a ComplianceDossier JSON file")
	fmt.Println("  --evaluation-file <path>    Path to an EvaluationResult JSON file")
	fmt.Println("  --db <path>                 Custom compliance database path")
	fmt.Println("  --json                      Output machine-readable JSON on stdout")
	fmt.Println("  --help, -h                  Show help")
	fmt.Println("\nExamples:")
	fmt.Println("  felix compliance limitations inspect --assessment ASM-01")
	fmt.Println("  felix compliance limitations inspect --dossier-file dossier.json")
	fmt.Println("  felix compliance limitations list --assessment ASM-01")
	fmt.Println("  felix compliance limitations check --dossier-file dossier.json")
	fmt.Println("  felix compliance limitations boundaries")
}

func runLimitationsBoundaries(args []string) int {
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		}
	}

	b := compliance.StandardDeterminationBoundaryStatement()
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(b)
		return clierror.ExitSuccess
	}

	fmt.Println("=== FELIX Compliance Determination Boundaries ===")
	fmt.Println("\n1. Technical Evidence:")
	fmt.Printf("   %s\n", b.TechnicalEvidenceNotice)
	fmt.Println("\n2. Control Mapping:")
	fmt.Printf("   %s\n", b.ControlMappingNotice)
	fmt.Println("\n3. Control Evaluation:")
	fmt.Printf("   %s\n", b.ControlEvaluationNotice)
	fmt.Println("\n4. Assessment Coverage:")
	fmt.Printf("   %s\n", b.AssessmentCoverageBasis)
	fmt.Println("\n5. Policy & Gate Decisions:")
	fmt.Printf("   %s\n", b.PolicyGateNotice)
	fmt.Println("\n6. Statutory Disclaimer:")
	fmt.Printf("   %s\n", b.FormalCertificationNote)
	return clierror.ExitSuccess
}

func runLimitationsInspect(args []string) int {
	var (
		assessmentID string
		catalogID    string
		dossierFile  string
		evalFile     string
		dbPath       string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
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
		case "--dossier-file", "-d", "--dossier":
			if i+1 < len(args) {
				dossierFile = args[i+1]
				i++
			}
		case "--evaluation-file", "--eval-file":
			if i+1 < len(args) {
				evalFile = args[i+1]
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
			printLimitationsHelp()
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && assessmentID == "" {
				assessmentID = arg
			}
		}
	}

	var eval *compliance.EvaluationResult
	var dossier *compliance.ComplianceDossier
	var err error

	if dossierFile != "" {
		dossier, err = compliance.LoadDossierFromFile(dossierFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading dossier %q: %v\n", dossierFile, err)
			return clierror.ExitOperational
		}
	} else if evalFile != "" {
		eval, err = loadEvaluationResultFromFile(evalFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading evaluation %q: %v\n", evalFile, err)
			return clierror.ExitOperational
		}
	} else if assessmentID != "" {
		store, storeErr := openComplianceStore(dbPath)
		if storeErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Error opening compliance store: %v\n", storeErr)
			return clierror.ExitOperational
		}
		defer store.Close()

		eval, err = store.GetEvaluationResult(assessmentID, catalogID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error retrieving evaluation for assessment %q: %v\n", assessmentID, err)
			return clierror.ExitOperational
		}
	} else {
		fmt.Fprintln(os.Stderr, "[-] Error: either --assessment, --dossier-file, or --evaluation-file is required")
		printLimitationsHelp()
		return clierror.ExitOperational
	}

	var cov compliance.CoverageBasis
	var lims []compliance.ComplianceLimitation

	if dossier != nil {
		if dossier.CoverageBasis != nil {
			cov = *dossier.CoverageBasis
		} else {
			cov = compliance.CalculateCoverageBasis(compliance.EvaluationSummary{
				TotalControls:             dossier.Summary.TotalControls,
				CompliantCount:            dossier.Summary.CompliantCount,
				NonCompliantCount:         dossier.Summary.NonCompliantCount,
				PartiallyCompliantCount:   dossier.Summary.PartiallyCompliantCount,
				NotAssessedCount:          dossier.Summary.NotAssessedCount,
				InsufficientEvidenceCount: dossier.Summary.InsufficientEvidenceCount,
				NotApplicableCount:        dossier.Summary.NotApplicableCount,
				ErrorCount:                dossier.Summary.ErrorCount,
				ApplicableControls:        dossier.Summary.ApplicableControls,
				AssessedControls:          dossier.Summary.AssessedControls,
			})
		}
		if len(dossier.StructuredLimitations) > 0 {
			lims = dossier.StructuredLimitations
		} else {
			lims = compliance.DeriveLimitationsFromDossier(dossier)
		}
	} else if eval != nil {
		if eval.CoverageBasis != nil {
			cov = *eval.CoverageBasis
		} else {
			cov = compliance.CalculateCoverageBasis(eval.Summary)
		}
		if len(eval.StructuredLimitations) > 0 {
			lims = eval.StructuredLimitations
		} else {
			lims = compliance.DeriveLimitationsFromEvaluation(eval, nil)
		}
	}

	if jsonOutput {
		out := map[string]any{
			"coverage_basis":         cov,
			"limitations":            lims,
			"determination_boundary": compliance.StandardDeterminationBoundaryStatement(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return clierror.ExitSuccess
	}

	targetID := assessmentID
	if dossier != nil {
		targetID = dossier.Identity.AssessmentID
	} else if eval != nil {
		targetID = eval.AssessmentID
	}

	fmt.Printf("=== FELIX Compliance Limitations & Determination Boundaries ===\n")
	fmt.Printf("Target Assessment:          %s\n", targetID)
	fmt.Printf("Coverage Confidence:        %s\n\n", cov.CoverageConfidence)

	fmt.Printf("Assessment Coverage Basis:\n")
	fmt.Printf("  Total Catalog Controls:   %d\n", cov.TotalCatalogControls)
	fmt.Printf("  Applicable Controls:      %d (Denominator basis: Total - NotApplicable)\n", cov.ApplicableControls)
	fmt.Printf("  Explicitly Not Applicable:%d (Excluded from denominator and numerator)\n", cov.NotApplicableControls)
	fmt.Printf("  Assessed Controls:        %d (%.1f%% evaluated coverage)\n", cov.AssessedControls, cov.AssessedCoveragePercent)
	fmt.Printf("  Unassessed Controls:      %d (Must NOT be assumed compliant)\n", cov.UnassessedControls)
	fmt.Printf("  Verified Compliant:       %d (%.1f%% compliance rate over applicable controls)\n", cov.CompliantControls, cov.ComplianceRatePercent)
	fmt.Printf("  Non-Compliant:            %d\n", cov.NonCompliantControls)
	fmt.Printf("  Partially Compliant:      %d\n", cov.PartiallyCompliantControls)
	fmt.Printf("  Insufficient Evidence:    %d\n", cov.InsufficientEvidenceControls)
	fmt.Printf("  Execution Errors:         %d\n", cov.ErrorControls)

	fmt.Printf("\nLimitation & Evidence Boundaries (%d recorded):\n", len(lims))
	for _, l := range lims {
		aff := ""
		if l.AffectedItem != "" {
			aff = fmt.Sprintf(" [%s]", l.AffectedItem)
		}
		fmt.Printf("  [%-8s] %-22s %s%s\n", l.Severity, l.ID, l.Title, aff)
		fmt.Printf("             %s\n", l.Description)
		if l.Remediation != "" {
			fmt.Printf("             Action: %s\n", l.Remediation)
		}
	}

	fmt.Printf("\nStatutory Boundary Notice:\n")
	fmt.Printf("  %s\n", compliance.FormalCertificationDisclaimer())

	return clierror.ExitSuccess
}

func runLimitationsList(args []string) int {
	var (
		assessmentID string
		catalogID    string
		dossierFile  string
		evalFile     string
		dbPath       string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
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
		case "--dossier-file", "-d", "--dossier":
			if i+1 < len(args) {
				dossierFile = args[i+1]
				i++
			}
		case "--evaluation-file", "--eval-file":
			if i+1 < len(args) {
				evalFile = args[i+1]
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

	var lims []compliance.ComplianceLimitation

	if dossierFile != "" {
		dossier, errLoad := compliance.LoadDossierFromFile(dossierFile)
		if errLoad != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading dossier: %v\n", errLoad)
			return clierror.ExitOperational
		}
		lims = compliance.DeriveLimitationsFromDossier(dossier)
	} else if evalFile != "" {
		eval, errLoad := loadEvaluationResultFromFile(evalFile)
		if errLoad != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading evaluation: %v\n", errLoad)
			return clierror.ExitOperational
		}
		lims = compliance.DeriveLimitationsFromEvaluation(eval, nil)
	} else if assessmentID != "" {
		store, storeErr := openComplianceStore(dbPath)
		if storeErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Error opening store: %v\n", storeErr)
			return clierror.ExitOperational
		}
		defer store.Close()
		eval, errGet := store.GetEvaluationResult(assessmentID, catalogID)
		if errGet != nil {
			fmt.Fprintf(os.Stderr, "[-] Error retrieving evaluation: %v\n", errGet)
			return clierror.ExitOperational
		}
		lims = compliance.DeriveLimitationsFromEvaluation(eval, nil)
	} else {
		fmt.Fprintln(os.Stderr, "[-] Error: --assessment, --dossier-file, or --evaluation-file is required")
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(lims)
		return clierror.ExitSuccess
	}

	fmt.Printf("%-8s  %-22s  %-15s  %-12s  %s\n", "SEVERITY", "LIMITATION ID", "CATEGORY", "AFFECTED", "TITLE")
	fmt.Printf("%-8s  %-22s  %-15s  %-12s  %s\n", "--------", "-------------", "--------", "--------", "-----")
	for _, l := range lims {
		aff := l.AffectedItem
		if aff == "" {
			aff = "-"
		}
		fmt.Printf("%-8s  %-22s  %-15s  %-12s  %s\n", l.Severity, l.ID, l.Category, aff, l.Title)
	}

	return clierror.ExitSuccess
}

func runLimitationsCheck(args []string) int {
	var (
		assessmentID string
		catalogID    string
		dossierFile  string
		evalFile     string
		dbPath       string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
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
		case "--dossier-file", "-d", "--dossier":
			if i+1 < len(args) {
				dossierFile = args[i+1]
				i++
			}
		case "--evaluation-file", "--eval-file":
			if i+1 < len(args) {
				evalFile = args[i+1]
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

	var eval *compliance.EvaluationResult
	if dossierFile != "" {
		dossier, err := compliance.LoadDossierFromFile(dossierFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading dossier: %v\n", err)
			return clierror.ExitOperational
		}
		cov := compliance.CalculateCoverageBasis(compliance.EvaluationSummary{
			TotalControls:             dossier.Summary.TotalControls,
			CompliantCount:            dossier.Summary.CompliantCount,
			NonCompliantCount:         dossier.Summary.NonCompliantCount,
			PartiallyCompliantCount:   dossier.Summary.PartiallyCompliantCount,
			NotAssessedCount:          dossier.Summary.NotAssessedCount,
			InsufficientEvidenceCount: dossier.Summary.InsufficientEvidenceCount,
			NotApplicableCount:        dossier.Summary.NotApplicableCount,
			ErrorCount:                dossier.Summary.ErrorCount,
			ApplicableControls:        dossier.Summary.ApplicableControls,
			AssessedControls:          dossier.Summary.AssessedControls,
		})
		lims := compliance.DeriveLimitationsFromDossier(dossier)
		if err := compliance.ValidateLimitations(lims); err != nil {
			if jsonOutput {
				out := map[string]any{"valid": false, "error": err.Error()}
				_ = json.NewEncoder(os.Stdout).Encode(out)
			} else {
				fmt.Fprintf(os.Stderr, "[-] Limitations validation failed: %v\n", err)
			}
			return clierror.ExitSecurityFail
		}
		if jsonOutput {
			out := map[string]any{"valid": true, "coverage_basis": cov, "limitations_count": len(lims)}
			_ = json.NewEncoder(os.Stdout).Encode(out)
		} else {
			fmt.Println("[+] Dossier limitations and determination boundaries are CONSISTENT and VALID")
		}
		return clierror.ExitSuccess
	}

	if evalFile != "" {
		var err error
		eval, err = loadEvaluationResultFromFile(evalFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading evaluation: %v\n", err)
			return clierror.ExitOperational
		}
	} else if assessmentID != "" {
		store, storeErr := openComplianceStore(dbPath)
		if storeErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Error opening store: %v\n", storeErr)
			return clierror.ExitOperational
		}
		defer store.Close()
		var err error
		eval, err = store.GetEvaluationResult(assessmentID, catalogID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error retrieving evaluation: %v\n", err)
			return clierror.ExitOperational
		}
	} else {
		fmt.Fprintln(os.Stderr, "[-] Error: --assessment, --dossier-file, or --evaluation-file is required")
		return clierror.ExitOperational
	}

	cov := compliance.CalculateCoverageBasis(eval.Summary)
	lims := compliance.DeriveLimitationsFromEvaluation(eval, nil)

	if err := compliance.ValidateDeterminationConsistency(eval, &cov, lims); err != nil {
		if jsonOutput {
			out := map[string]any{"valid": false, "error": err.Error()}
			_ = json.NewEncoder(os.Stdout).Encode(out)
		} else {
			fmt.Fprintf(os.Stderr, "[-] Determination consistency check FAILED: %v\n", err)
		}
		return clierror.ExitSecurityFail
	}

	if jsonOutput {
		out := map[string]any{"valid": true, "coverage_basis": cov, "limitations_count": len(lims)}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Println("[+] Evaluation limitations and determination boundaries are CONSISTENT and VALID")
	}

	return clierror.ExitSuccess
}

func loadEvaluationResultFromFile(path string) (*compliance.EvaluationResult, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var res compliance.EvaluationResult
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}
