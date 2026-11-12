package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"felix/pkg/investigation"
	"felix/pkg/report"
	"felix/pkg/validation"
)

func runValidate(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printValidateHelp()
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "hash-gt":
		return runValidateHashGT(subArgs)
	case "verify-auth":
		return runValidateVerifyAuth(subArgs)
	case "evaluate":
		return runValidateEvaluate(subArgs)
	case "pilot-readiness", "readiness":
		return runValidatePilotReadiness(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown validate subcommand %q\n\n", sub)
		printValidateHelp()
		return 2
	}
}

func runValidateHashGT(args []string) int {
	var gtPath string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--ground-truth" && i+1 < len(args):
			gtPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ground-truth="):
			gtPath = strings.TrimPrefix(args[i], "--ground-truth=")
		}
	}
	if strings.TrimSpace(gtPath) == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --ground-truth <file.json> is required")
		return 2
	}
	b, err := os.ReadFile(gtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading ground-truth file: %v\n", err)
		return 2
	}
	var reg validation.GroundTruthRegistry
	if err := json.Unmarshal(b, &reg); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing ground-truth JSON: %v\n", err)
		return 2
	}
	digest, err := validation.CanonicalGroundTruthSHA256(&reg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error hashing ground-truth registry: %v\n", err)
		return 2
	}
	fmt.Println(digest)
	return 0
}

func runValidateVerifyAuth(args []string) int {
	var manifestPath, targetURL, groundTruthPath string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--manifest" && i+1 < len(args):
			manifestPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--manifest="):
			manifestPath = strings.TrimPrefix(args[i], "--manifest=")
		case args[i] == "--target" && i+1 < len(args):
			targetURL = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--target="):
			targetURL = strings.TrimPrefix(args[i], "--target=")
		case args[i] == "--ground-truth" && i+1 < len(args):
			groundTruthPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ground-truth="):
			groundTruthPath = strings.TrimPrefix(args[i], "--ground-truth=")
		}
	}
	if strings.TrimSpace(manifestPath) == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --manifest <file.json> is required")
		return 2
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading manifest: %v\n", err)
		return 2
	}

	contract, cm, err := validation.ParseAuthOrCampaignManifest(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing manifest JSON: %v\n", err)
		return 2
	}
	if targetURL == "" {
		if cm != nil && cm.TargetURL != "" {
			targetURL = cm.TargetURL
		} else if len(contract.AuthorizedTargets) > 0 {
			targetURL = contract.AuthorizedTargets[0]
		}
	}

	if err := validation.ValidateAuthorizationGate(contract, targetURL, time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization gate failed: %v\n", err)
		return 2
	}
	if cm != nil {
		if err := validation.ValidateGroundTruthSHA256Format(cm.GroundTruthSHA256); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Authorization gate failed: %v\n", err)
			return 2
		}
	}
	if strings.TrimSpace(groundTruthPath) != "" {
		gtBytes, gtErr := os.ReadFile(groundTruthPath)
		if gtErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading ground truth %q: %v\n", groundTruthPath, gtErr)
			return 2
		}
		var reg validation.GroundTruthRegistry
		if uErr := json.Unmarshal(gtBytes, &reg); uErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Error parsing ground truth JSON: %v\n", uErr)
			return 2
		}
		if reg.DerivedFromScanner {
			fmt.Fprintln(os.Stderr, "[-] Ground-truth integrity check failed: derived_from_scanner=true")
			return 2
		}
		if len(reg.Entries) == 0 {
			fmt.Fprintln(os.Stderr, "[-] Ground-truth integrity check failed: registry has zero entries")
			return 2
		}
		computed, hErr := validation.CanonicalGroundTruthSHA256(&reg)
		if hErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Ground-truth hashing failed: %v\n", hErr)
			return 2
		}
		if cm == nil {
			fmt.Fprintln(os.Stderr, "[-] Ground-truth verification failed: --ground-truth requires a CampaignManifest with ground_truth_sha256")
			return 2
		}
		if !strings.EqualFold(strings.TrimSpace(cm.GroundTruthSHA256), computed) {
			fmt.Fprintf(os.Stderr, "[-] Ground-truth digest mismatch: manifest=%s computed=%s\n", cm.GroundTruthSHA256, computed)
			return 2
		}
	}
	fmt.Printf("[+] Authorization gate verified for %s (authorizer=%s, ref=%s)\n", targetURL, contract.AuthorizingParty, contract.AuthorizationRef)
	return 0
}

func runValidateEvaluate(args []string) int {
	var gtPath, repPath, authzPath, retestPath, retestExpPath, manifestPath, outPath string
	var jsonStdout bool

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--ground-truth" && i+1 < len(args):
			gtPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--ground-truth="):
			gtPath = strings.TrimPrefix(a, "--ground-truth=")
		case a == "--report" && i+1 < len(args):
			repPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--report="):
			repPath = strings.TrimPrefix(a, "--report=")
		case a == "--authz" && i+1 < len(args):
			authzPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--authz="):
			authzPath = strings.TrimPrefix(a, "--authz=")
		case a == "--retest" && i+1 < len(args):
			retestPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--retest="):
			retestPath = strings.TrimPrefix(a, "--retest=")
		case a == "--retest-expected" && i+1 < len(args):
			retestExpPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--retest-expected="):
			retestExpPath = strings.TrimPrefix(a, "--retest-expected=")
		case a == "--manifest" && i+1 < len(args):
			manifestPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--manifest="):
			manifestPath = strings.TrimPrefix(a, "--manifest=")
		case (a == "--output" || a == "-o") && i+1 < len(args):
			outPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--output="):
			outPath = strings.TrimPrefix(a, "--output=")
		case a == "--json":
			jsonStdout = true
		}
	}

	if strings.TrimSpace(gtPath) == "" || strings.TrimSpace(repPath) == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --ground-truth and --report are required")
		printValidateHelp()
		return 2
	}

	gtBytes, err := os.ReadFile(gtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading ground-truth: %v\n", err)
		return 2
	}
	var reg validation.GroundTruthRegistry
	if err := json.Unmarshal(gtBytes, &reg); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing ground-truth JSON: %v\n", err)
		return 2
	}

	repBytes, err := os.ReadFile(repPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading report: %v\n", err)
		return 2
	}
	var rep report.Report
	if err := json.Unmarshal(repBytes, &rep); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing assessment report JSON: %v\n", err)
		return 2
	}

	var authz *report.AuthorizationReportSummary
	if authzPath != "" {
		if b, err := os.ReadFile(authzPath); err == nil {
			var az report.AuthorizationReportSummary
			if json.Unmarshal(b, &az) == nil {
				authz = &az
			}
		}
	}

	var retestVerdicts []*investigation.RetestVerdict
	if retestPath != "" {
		if b, err := os.ReadFile(retestPath); err == nil {
			var rr struct {
				Verdicts []*investigation.RetestVerdict `json:"verdicts"`
			}
			if json.Unmarshal(b, &rr) == nil {
				retestVerdicts = rr.Verdicts
			}
		}
	}

	var retestExp []validation.RetestExpectedItem
	if retestExpPath != "" {
		if b, err := os.ReadFile(retestExpPath); err == nil {
			_ = json.Unmarshal(b, &retestExp)
		}
	}

	var manifest *validation.CampaignManifest
	if manifestPath != "" {
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading manifest: %v\n", err)
			return 2
		}
		var cm validation.CampaignManifest
		if err := json.Unmarshal(b, &cm); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error parsing manifest JSON: %v\n", err)
			return 2
		}
		manifest = &cm
	}

	eval, err := validation.EvaluateAccuracy(&reg, &rep, authz, retestVerdicts, retestExp, manifest, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error evaluating accuracy: %v\n", err)
		return 2
	}

	outBytes, _ := json.MarshalIndent(eval, "", "  ")
	if outPath != "" {
		if err := os.WriteFile(outPath, outBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error writing output %q: %v\n", outPath, err)
			return 2
		}
	}

	if jsonStdout {
		fmt.Println(string(outBytes))
	} else {
		fmt.Printf("FELIX Phase 8 Accuracy Evaluation: %s (Registry: %s)\n", eval.TargetName, eval.RegistryID)
		fmt.Printf("  Blind Integrity Verified: %v | Redaction Clean: %v | Summary Sync: %v\n",
			eval.BlindExecutionVerified, eval.RedactionAudit.Clean, eval.ReportSummaryConsistent)
		fmt.Printf("  Confusion Counts: TP=%d FP=%d FN=%d TN=%d Inconclusive=%d NotTested=%d NotConfigured=%d SafetyExcl=%d OOS=%d\n",
			eval.Counts.TP, eval.Counts.FP, eval.Counts.FN, eval.Counts.TN,
			eval.Counts.Inconclusive, eval.Counts.NotTested, eval.Counts.NotConfigured,
			eval.Counts.SafetyExcluded, eval.Counts.OutOfScope)
		printRate := func(name string, r validation.MetricRate) {
			if !r.Valid {
				fmt.Printf("  %-20s N/A (%s)\n", name+":", r.InvalidReason)
				return
			}
			fmt.Printf("  %-20s %.2f%% (%d/%d, 95%% Wilson CI: [%.2f%%, %.2f%%])\n",
				name+":", r.Value*100, r.Numerator, r.Denominator, r.CI95.Lower95*100, r.CI95.Upper95*100)
		}
		printRate("Precision", eval.Precision)
		printRate("Recall", eval.Recall)
		printRate("Specificity", eval.Specificity)
		printRate("Execution Coverage", eval.ExecutionCoverage)
		if outPath != "" {
			fmt.Printf("  Saved JSON: %s\n", outPath)
		}
	}
	return 0
}

func runValidatePilotReadiness(args []string) int {
	var (
		opts       validation.PilotReadinessOptions
		outPath    string
		jsonStdout bool
	)
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--manifest" && i+1 < len(args):
			opts.ManifestPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--manifest="):
			opts.ManifestPath = strings.TrimPrefix(args[i], "--manifest=")
		case (args[i] == "--auth-contract" || args[i] == "--auth") && i+1 < len(args):
			opts.AuthorizationPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--auth-contract="):
			opts.AuthorizationPath = strings.TrimPrefix(args[i], "--auth-contract=")
		case args[i] == "--ground-truth" && i+1 < len(args):
			opts.GroundTruthPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ground-truth="):
			opts.GroundTruthPath = strings.TrimPrefix(args[i], "--ground-truth=")
		case args[i] == "--roles-config" && i+1 < len(args):
			opts.RolesConfigPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--roles-config="):
			opts.RolesConfigPath = strings.TrimPrefix(args[i], "--roles-config=")
		case args[i] == "--retest-expected" && i+1 < len(args):
			opts.RetestExpectedPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--retest-expected="):
			opts.RetestExpectedPath = strings.TrimPrefix(args[i], "--retest-expected=")
		case args[i] == "--baseline-report" && i+1 < len(args):
			opts.BaselineReportPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--baseline-report="):
			opts.BaselineReportPath = strings.TrimPrefix(args[i], "--baseline-report=")
		case args[i] == "--target" && i+1 < len(args):
			opts.TargetURL = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--target="):
			opts.TargetURL = strings.TrimPrefix(args[i], "--target=")
		case args[i] == "--output-dir" && i+1 < len(args):
			opts.OutputDir = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--output-dir="):
			opts.OutputDir = strings.TrimPrefix(args[i], "--output-dir=")
		case args[i] == "--binary" && i+1 < len(args):
			opts.BinaryPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--binary="):
			opts.BinaryPath = strings.TrimPrefix(args[i], "--binary=")
		case args[i] == "--oast-server" && i+1 < len(args):
			opts.OASTServerURL = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--oast-server="):
			opts.OASTServerURL = strings.TrimPrefix(args[i], "--oast-server=")
		case args[i] == "--require-public-signoff":
			opts.RequirePublicReleaseSignoff = true
		case (args[i] == "--output" || args[i] == "-o") && i+1 < len(args):
			outPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--output="):
			outPath = strings.TrimPrefix(args[i], "--output=")
		case args[i] == "--json":
			jsonStdout = true
		}
	}

	rep := validation.EvaluatePilotReadiness(opts)
	outBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error marshaling readiness report: %v\n", err)
		return 2
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, outBytes, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error writing output %q: %v\n", outPath, err)
			return 2
		}
	}

	if jsonStdout {
		fmt.Println(string(outBytes))
	} else {
		fmt.Printf("FELIX Pilot Readiness Check: overall=%s pilot_execution=%s public_release=%s (external_requests=%d)\n",
			rep.OverallStatus, rep.PilotExecutionStatus, rep.PublicReleaseStatus, rep.ExternalRequestsSent)
		for _, c := range rep.Checks {
			fmt.Printf("  [%02d] %-14s %-38s %s\n", c.Number, c.Status, c.ID, c.Detail)
		}
		if outPath != "" {
			fmt.Printf("  Saved JSON: %s\n", outPath)
		}
	}
	if rep.OverallStatus != validation.ReadinessReady {
		return 2
	}
	return 0
}

func printValidateHelp() {
	fmt.Println("Usage: felix validate <subcommand> [flags]")
	fmt.Println("\nPhase 8 / 10A Real-World Accuracy Validation & Readiness Subcommands:")
	fmt.Println("  hash-gt          Compute deterministic SHA-256 lock hash for an independent ground-truth registry")
	fmt.Println("  verify-auth      Verify authorization contract scope, exclusions, UTC window, and campaign GT digest")
	fmt.Println("  evaluate         Compare FELIX assessment/authz/retest reports against a hash-locked ground truth")
	fmt.Println("  pilot-readiness  Run 16-point offline onboarding readiness & prerequisite checker (0 network traffic)")
	fmt.Println("\nVerify-Auth Flags:")
	fmt.Println("  --manifest <path>         AuthorizationContract or CampaignManifest JSON (required)")
	fmt.Println("  --target <url>            Target URL to verify against manifest scope (optional)")
	fmt.Println("  --ground-truth <path>     Verify canonical SHA-256 against CampaignManifest ground_truth_sha256 (optional)")
	fmt.Println("\nPilot-Readiness Flags:")
	fmt.Println("  --manifest <path>         Campaign manifest JSON (optional)")
	fmt.Println("  --auth-contract <path>    Standalone authorization contract JSON (optional)")
	fmt.Println("  --ground-truth <path>     Independent ground-truth JSON registry (optional)")
	fmt.Println("  --roles-config <path>     Multi-role test identities JSON (optional)")
	fmt.Println("  --retest-expected <path>  Retest expectation JSON array (optional)")
	fmt.Println("  --output-dir <path>       Campaign output directory to verify private write permissions (optional)")
	fmt.Println("  --binary <path>           Path to FELIX binary to hash/verify (optional)")
	fmt.Println("  --output, -o <path>       Write machine-readable PilotReadinessReport JSON")
	fmt.Println("  --json                    Print JSON output to stdout")
	fmt.Println("\nEvaluate Flags:")
	fmt.Println("  --ground-truth <path>     Independent ground-truth JSON registry (required)")
	fmt.Println("  --report <path>           FELIX assessment_report.json (required)")
	fmt.Println("  --authz <path>            FELIX authorization_summary.json (optional)")
	fmt.Println("  --retest <path>           FELIX retest_report.json (optional)")
	fmt.Println("  --retest-expected <path>  Expected retest outcomes JSON (optional)")
	fmt.Println("  --manifest <path>         Campaign manifest JSON for blindness & auth verification (optional)")
	fmt.Println("  --output, -o <path>       Write machine-readable AccuracyEvaluationReport JSON")
	fmt.Println("  --json                    Print JSON output to stdout")
}
