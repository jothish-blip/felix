package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/crawler"
	_ "felix/pkg/crawler/browser"
)

const banner = `
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================
`

func run(args []string) int {
	if len(args) == 0 {
		printRootHelp()
		return clierror.ExitSuccess
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	// Unified Assessment Orchestrator
	case "assess":
		return runAssess(subArgs)

	// Core & Meta Commands
	case "capabilities":
		return runCapabilities(subArgs)
	case "doctor":
		return runDoctor(subArgs)
	case "config":
		return runConfig(subArgs)
	case "version", "--version", "-V":
		if os.Getenv("FELIX_TEST_FAIL_VERSION") == "true" {
			if Release == "TestBuild" || strings.Contains(strings.ToLower(Release), "test") || GitCommit == "dev" {
				fmt.Fprintln(os.Stderr, "[-] Simulated failure in version diagnostic (isolated test hook)")
				return 2
			}
			fmt.Fprintln(os.Stderr, "[!] Warning: FELIX_TEST_FAIL_VERSION test hook is ignored in production release builds.")
		}
		return runVersion(subArgs)

	// Security Audit Modules
	case "recon":
		return runRecon(subArgs)
	case "scan":
		return runScan(subArgs)
	case "web", "vuln", "webvuln":
		return runDirectModule("web", runAssessmentWebVuln, subArgs)
	case "api", "apisec":
		return runDirectModule("api", runAssessmentAPISec, subArgs)
	case "auth":
		return runDirectModule("auth", runAssessmentAuth, subArgs)
	case "authz":
		return runDirectModule("authz", runAssessmentAuthz, subArgs)
	case "bola", "idor":
		return runDirectModule("bola", runAssessmentBOLA, subArgs)
	case "bfla":
		return runDirectModule("bfla", runAssessmentBFLA, subArgs)
	case "bopla":
		return runDirectModule("bopla", runAssessmentBOPLA, subArgs)
	case "secrets":
		return runSecrets(subArgs)
	case "cloud", "cloudsec":
		return runDirectModule("cloud", runAssessmentCloudSec, subArgs)
	case "mobile", "apk":
		return runAPK(subArgs)
	case "cve":
		return runCVE(subArgs)
	case "oast":
		return runOAST(subArgs)

	// Assessment Projects & Operations
	case "target":
		return runTarget(subArgs)
	case "monitor":
		return runMonitor(subArgs)
	case "ci":
		return runCI(subArgs)
	case "client":
		return runClient(subArgs)
	case "compliance":
		return runCompliance(subArgs)
	case "assessment":
		return runAssessment(subArgs)
	case "schedule", "schedules":
		return runAssessmentSchedule(subArgs)
	case "history":
		return runAssessmentHistory(subArgs)
	case "diff":
		return runAssessmentDiff(subArgs)
	case "summary":
		return runAssessmentSummary(subArgs)
	case "recover":
		return runAssessmentRecover(subArgs)
	case "notification", "notifications", "alert", "alerts":
		return runNotification(subArgs)
	case "operator":
		return runOperator(subArgs)

	// Governance & Reporting
	case "report":
		return runReport(subArgs)
	case "license", "licensing":
		return runLicense(subArgs)

	// System Utilities
	case "install":
		return runInstall(subArgs)
	case "uninstall":
		return runUninstall(subArgs)
	case "completion":
		return runCompletion(subArgs)
	case "update":
		return runUpdate(subArgs)

	// Help System
	case "help", "--help", "-h":
		if len(subArgs) > 0 {
			sub := subArgs[0]
			switch sub {
			case "assess":
				return runAssess([]string{"--help"})
			case "capabilities":
				return runCapabilities([]string{"--help"})
			case "recon":
				return runRecon([]string{"--help"})
			case "scan":
				return runScan([]string{"--help"})
			case "web", "vuln", "webvuln":
				return runAssessmentWebVuln([]string{"--help"})
			case "api", "apisec":
				return runAssessmentAPISec([]string{"--help"})
			case "auth":
				return runAssessmentAuth([]string{"--help"})
			case "authz":
				return runAssessmentAuthz([]string{"--help"})
			case "bola", "idor":
				return runAssessmentBOLA([]string{"--help"})
			case "bfla":
				return runAssessmentBFLA([]string{"--help"})
			case "bopla":
				return runAssessmentBOPLA([]string{"--help"})
			case "secrets":
				return runSecrets([]string{"--help"})
			case "cloud", "cloudsec":
				return runAssessmentCloudSec([]string{"--help"})
			case "mobile", "apk":
				return runAPK([]string{"--help"})
			case "cve":
				return runCVE([]string{"--help"})
			case "oast":
				return runOAST([]string{"--help"})
			case "target":
				return runTarget([]string{"--help"})
			case "monitor":
				return runMonitor([]string{"--help"})
			case "ci":
				return runCI([]string{"--help"})
			case "report":
				return runReport([]string{"--help"})
			case "client":
				return runClient([]string{"--help"})
			case "compliance":
				return runCompliance([]string{"--help"})
			case "license", "licensing":
				return runLicense([]string{"--help"})
			case "assessment":
				return runAssessment([]string{"--help"})
			case "schedule":
				return runAssessmentSchedule([]string{"--help"})
			case "history":
				return runAssessmentHistory([]string{"--help"})
			case "diff":
				return runAssessmentDiff([]string{"--help"})
			case "operator":
				return runOperator([]string{"--help"})
			case "config":
				return runConfig([]string{"--help"})
			case "doctor":
				return runDoctor([]string{"--help"})
			case "notification", "notifications", "alert", "alerts":
				return runNotification([]string{"--help"})
			case "update":
				return runUpdate([]string{"--help"})
			case "completion":
				return runCompletion([]string{"--help"})
			case "install":
				return runInstall([]string{"--help"})
			case "uninstall":
				return runUninstall([]string{"--help"})
			case "version":
				return runVersion([]string{"--help"})
			default:
				printRootHelp()
				return clierror.ExitSuccess
			}
		}
		printRootHelp()
		return clierror.ExitSuccess
	default:
		// If argument starts with '-' or looks like a URL/target, treat as 'scan' for convenience
		if strings.HasPrefix(cmd, "-") || strings.Contains(cmd, "://") || strings.Contains(cmd, ".") {
			return runScan(args)
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown command: %s\n\n", cmd)
		printRootHelp()
		return clierror.ExitOperational
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func printRootHelp() {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  felix <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("\n  Unified Assessment:")
	fmt.Println("    assess        Execute unified end-to-end security assessment across defined profiles")
	fmt.Println("\n  Security Audit Modules:")
	fmt.Println("    recon         Automated zero-credential attack-surface and asset discovery")
	fmt.Println("    scan          Audit target web applications for security exposures")
	fmt.Println("    web           Audit targets for OWASP Top 10 web vulnerabilities (SQLi, XSS, SSRF)")
	fmt.Println("    api           REST/GraphQL API security analysis and OpenAPI schema validation")
	fmt.Println("    auth          Authentication surface, token validity, and session boundary audits")
	fmt.Println("    authz         Authorization matrix and privilege escalation analysis")
	fmt.Println("    bola          Broken Object Level Authorization (IDOR) engine")
	fmt.Println("    bfla          Broken Function Level Authorization and admin route bypass checks")
	fmt.Println("    bopla         Broken Object Property Level Authorization (Mass Assignment) audit")
	fmt.Println("    secrets       Scan files, URLs, or text for high-entropy secrets and exposed keys")
	fmt.Println("    cloud         Cloud asset and object storage exposure auditing (S3, Blob, GCP)")
	fmt.Println("    mobile        Audit Android APK packages (alias for apk)")
	fmt.Println("    cve           Query local SQLite CVE database with SemVer matching")
	fmt.Println("    oast          Out-of-band application security testing and callback listener")
	fmt.Println("\n  Assessment Projects & Operations:")
	fmt.Println("    assessment    Manage authorized security assessment projects, scopes, and runs")
	fmt.Println("    target        Manage and validate declarative multi-tenant target profiles")
	fmt.Println("    schedule      Manage recurring assessment schedules and automated execution")
	fmt.Println("    history       View persistent execution history for assessments and schedules")
	fmt.Println("    diff          Compare assessment runs to identify finding deltas and regressions")
	fmt.Println("    summary       Display executive summary metrics across assessment runs")
	fmt.Println("    recover       Recover interrupted or paused assessment executions")
	fmt.Println("    notification  Manage alerting, webhooks, and outbox notification delivery")
	fmt.Println("    operator      Launch local-first operator console for assessment curation")
	fmt.Println("    client        Manage clients and organizations for structured assessments")
	fmt.Println("    monitor       Temporal drift detection and instant webhook alerting for API surfaces")
	fmt.Println("    ci            Execute automated security assessments for CI/CD pipelines")
	fmt.Println("    compliance    Manage compliance catalogs, mapping, evaluations, SLAs, and MTTR")
	fmt.Println("\n  Governance & Reporting:")
	fmt.Println("    report        Generate assessment reports from existing scan results (zero network)")
	fmt.Println("    license       Manage enterprise licensing, metered usage quotas, and signed exports")
	fmt.Println("\n  Core & System Utilities:")
	fmt.Println("    capabilities  List all registered assessment engines, maturity status, and license tiers")
	fmt.Println("    doctor        Diagnose environment, network stack, and permissions")
	fmt.Println("    config        Manage persistent CLI configuration settings")
	fmt.Println("    version       Display Felix version and build environment")
	fmt.Println("    update        Check for or install verified updates from official releases")
	fmt.Println("    install       Install Felix binary to user system PATH")
	fmt.Println("    uninstall     Remove Felix binary from system PATH")
	fmt.Println("    completion    Generate shell autocompletion script")
	fmt.Println("    help          Show help for Felix or a specific command")
	fmt.Println("\nQuick Start:")
	fmt.Println("  felix assess --target https://example.com --profile standard --output ./audit_results")
	fmt.Println("  felix recon --target https://example.com")
	fmt.Println("  felix secrets --file ./config.json")
	fmt.Println("  felix scan https://example.com --export report.html --json scan.json")
	fmt.Println("  felix capabilities")
	fmt.Println("  felix doctor")
	fmt.Println("\nRun 'felix <command> --help' for details on a specific command.")
}

func assetLabel(t crawler.AssetType) string {
	switch t {
	case crawler.AssetJavaScript:
		return "JS"
	case crawler.AssetStylesheet:
		return "CSS"
	case crawler.AssetSourceMap:
		return "MAP"
	case crawler.AssetManifest:
		return "MANIFEST"
	default:
		return "ASSET"
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
