package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runCompliance(args []string) int {
	if len(args) == 0 {
		printComplianceHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "catalog", "catalogs":
		return runComplianceCatalog(subArgs)
	case "mapping", "mappings":
		return runComplianceMapping(subArgs)
	case "evaluate", "eval", "run":
		return runComplianceEvaluate(subArgs)
	case "evaluation", "evaluations", "result", "results":
		return runComplianceEvaluation(subArgs)
	case "verify", "verification", "check", "integrity":
		return runComplianceVerify(subArgs)
	case "sla", "remediation":
		return runComplianceSLA(subArgs)
	case "mttr":
		return runComplianceMTTR(subArgs)
	case "dossier":
		return runComplianceDossier(subArgs)
	case "export", "exports":
		return runComplianceExport(subArgs)
	case "gate", "gates":
		return runComplianceGate(subArgs)
	case "limitations", "limitation", "boundaries":
		return runComplianceLimitations(subArgs)
	case "help", "--help", "-h":
		printComplianceHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown compliance command: %s\n\n", sub)
		printComplianceHelp()
		return clierror.ExitOperational
	}
}

func printComplianceHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  catalog      Manage and inspect compliance control catalogs")
	fmt.Println("  mapping      Manage and execute finding-to-control mapping rulesets")
	fmt.Println("  evaluate     Execute evidence-backed compliance evaluations against controls")
	fmt.Println("  evaluation   Inspect persisted evaluation results, control outcomes, and evidence")
	fmt.Println("  verify       Verify cryptographic integrity and authenticity of compliance evaluations")
	fmt.Println("  sla          Manage and track remediation SLAs and lifecycle status")
	fmt.Println("  mttr         Calculate Mean Time to Remediation metrics using verified lifecycle data")
	fmt.Println("  dossier      Generate and validate evidence-backed compliance dossiers")
	fmt.Println("  export       Export compliance records in normalized JSON or NIST OSCAL format")
	fmt.Println("  gate         Evaluate compliance gates for CI/CD pipelines against policies")
	fmt.Println("  limitations  Inspect assessment limitations, explicit coverage basis, and determination boundaries")
	fmt.Println("  help         Display this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  felix compliance catalog validate catalog.json")
	fmt.Println("  felix compliance mapping validate mapping.json --catalog catalog.json")
	fmt.Println("  felix compliance evaluate --assessment ASM-01 --catalog catalog.json --save")
	fmt.Println("  felix compliance evaluation list")
	fmt.Println("  felix compliance verify --assessment ASM-01")
	fmt.Println("  felix compliance sla list --overdue")
	fmt.Println("  felix compliance mttr --from 2026-01-01")
	fmt.Println("  felix compliance dossier generate --assessment ASM-01 --catalog nist-sp-800-53:5.1.0")
	fmt.Println("  felix compliance export oscal --assessment ASM-01 --catalog nist-sp-800-53:5.1.0")
	fmt.Println("  felix compliance gate --policy gate.json --assessment ASM-01")
}

func runComplianceVerify(args []string) int {
	var (
		assessmentID string
		catalogID    string
		resultID     string
		keyFilePath  string
		keyEnvVar    string
		keyID        string
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
		case "--result-id", "--id":
			if i+1 < len(args) {
				resultID = args[i+1]
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
					fmt.Fprintln(os.Stderr, "[-] Error: Passing raw key secrets directly via command-line arguments is disabled for security (visible in process lists and shell history). Use --key-file <path> or set FELIX_COMPLIANCE_KEY.")
					return clierror.ExitOperational
				}
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
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printVerifyHelp()
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

	if resultID == "" && assessmentID == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: either --assessment or --result-id must be provided")
		return clierror.ExitOperational
	}

	// Open compliance store
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	// Initialize KeyProvider
	keyProvider, err := resolveKeyProvider(keyFilePath, keyEnvVar, keyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid key configuration: %v\n", err)
		return clierror.ExitOperational
	}

	lookupAss := assessmentID
	lookupCat := catalogID
	if resultID != "" {
		lookupAss = resultID
		lookupCat = ""
	}

	result, err := store.VerifyEvaluationIntegrity(lookupAss, lookupCat, keyProvider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational failure during integrity verification: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	} else {
		fmt.Printf("=== FELIX Compliance Integrity Verification ===\n")
		fmt.Printf("Result ID:          %s\n", result.ResultID)
		fmt.Printf("Assessment ID:      %s\n", result.AssessmentID)
		fmt.Printf("Catalog Identity:   %s\n", result.CatalogIdentity)
		fmt.Printf("Integrity Status:   %s\n", result.Status)
		fmt.Printf("Content Digest:     %t\n", result.ContentDigestMatch)
		fmt.Printf("Authenticity (HMAC): %t\n", result.AuthenticityMatch)
		if result.KeyID != "" {
			fmt.Printf("Key ID:             %s\n", result.KeyID)
		}
		fmt.Printf("Evidence Links:     %d\n", result.EvidenceIntegrity.TotalEvidenceLinks)
		fmt.Printf("Evidence Metadata:  %t\n", result.EvidenceIntegrity.MetadataVerified)

		switch result.Status {
		case compliance.StatusVerified:
			fmt.Printf("\n[+] SUCCESS: Cryptographic integrity and authenticity verified (HMAC-SHA256).\n")
		case compliance.StatusIntegrityOnly:
			fmt.Printf("\n[!] NOTICE: Content integrity verified (SHA-256), but record has NO cryptographic authenticity (unauthenticated hash mode).\n")
			fmt.Printf("    An attacker with direct database write access could forge both content and digest.\n")
		case compliance.StatusIntegrityMismatch:
			fmt.Printf("\n[!] SECURITY ALERT: Cryptographic integrity verification FAILED (tampering or corruption detected).\n")
		case compliance.StatusUnknownKey:
			fmt.Printf("\n[-] WARNING: Record is HMAC-protected, but verification key is unknown, missing, or retired.\n")
			fmt.Printf("    Configure the verification key via --key-file <path> or FELIX_COMPLIANCE_KEY.\n")
		case compliance.StatusUnverifiedLegacy:
			fmt.Printf("\n[-] NOTICE: Evaluation record was persisted without integrity protection (legacy unverified record).\n")
		case compliance.StatusVerificationUnavailable:
			fmt.Printf("\n[-] ERROR: Verification prerequisites unavailable (key provider misconfigured).\n")
		case compliance.StatusOperationalFailure:
			fmt.Printf("\n[-] ERROR: Operational or database error prevented verification.\n")
		}

		if len(result.Violations) > 0 {
			fmt.Printf("\nIntegrity Violations (%d):\n", len(result.Violations))
			for i, v := range result.Violations {
				fmt.Printf("  [%d] %s\n", i+1, v)
			}
		}
	}

	switch result.Status {
	case compliance.StatusVerified, compliance.StatusIntegrityOnly:
		return clierror.ExitSuccess
	case compliance.StatusIntegrityMismatch:
		return clierror.ExitSecurityFail
	default:
		return clierror.ExitOperational
	}
}

func printVerifyHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance verify [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  --assessment <id>, -a <id>   Assessment ID to verify (required unless --result-id is provided)")
	fmt.Println("  --catalog <id>, -c <id>      Catalog ID to disambiguate evaluations")
	fmt.Println("  --result-id <id>             Direct evaluation result record ID")
	fmt.Println("  --key-file <path>            Path to HMAC verification key file")
	fmt.Println("  --key-env <var>              Environment variable containing verification key")
	fmt.Println("  --key-id <id>                Key ID for multi-key providers")
	fmt.Println("  --db <path>                  Custom SQLite compliance database path")
	fmt.Println("  --json                       Output machine-readable JSON")
	fmt.Println("  --help, -h                   Show help")
}
