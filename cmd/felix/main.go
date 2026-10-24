package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/crawler"
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
	case "scan":
		return runScan(subArgs)
	case "target":
		return runTarget(subArgs)
	case "monitor":
		return runMonitor(subArgs)
	case "ci":
		return runCI(subArgs)
	case "apk":
		return runAPK(subArgs)
	case "report":
		return runReport(subArgs)
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
	case "config":
		return runConfig(subArgs)
	case "doctor":
		return runDoctor(subArgs)
	case "version", "--version", "-V":
		if os.Getenv("FELIX_TEST_FAIL_VERSION") == "true" {
			if Release == "TestBuild" || strings.Contains(strings.ToLower(Release), "test") || GitCommit == "dev" {
				fmt.Fprintln(os.Stderr, "[-] Simulated failure in version diagnostic (isolated test hook)")
				return 2
			}
			fmt.Fprintln(os.Stderr, "[!] Warning: FELIX_TEST_FAIL_VERSION test hook is ignored in production release builds.")
		}
		return runVersion(subArgs)
	case "install":
		return runInstall(subArgs)
	case "uninstall":
		return runUninstall(subArgs)
	case "completion":
		return runCompletion(subArgs)
	case "update":
		return runUpdate(subArgs)
	case "help", "--help", "-h":
		if len(subArgs) > 0 {
			sub := subArgs[0]
			switch sub {
			case "scan":
				return runScan([]string{"--help"})
			case "target":
				return runTarget([]string{"--help"})
			case "monitor":
				return runMonitor([]string{"--help"})
			case "ci":
				return runCI([]string{"--help"})
			case "apk":
				return runAPK([]string{"--help"})
			case "report":
				return runReport([]string{"--help"})
			case "client":
				return runClient([]string{"--help"})
			case "compliance":
				return runCompliance([]string{"--help"})
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
	fmt.Println("  scan        Audit target web applications for security exposures")
	fmt.Println("  target      Manage and validate declarative multi-tenant target profiles")
	fmt.Println("  monitor     Temporal drift detection and instant webhook alerting for API surfaces")
	fmt.Println("  ci          Execute automated security assessments for CI/CD pipelines")
	fmt.Println("  apk         Validate, isolate, and audit Android APK packages (generates mobile_audit.html)")
	fmt.Println("  report      Generate assessment reports from existing scan results (zero network)")
	fmt.Println("  compliance  Manage compliance catalogs, mapping, evaluations, integrity, SLAs, MTTR, and exports")
	fmt.Println("  client      Manage clients and organizations for structured assessments")
	fmt.Println("  assessment  Manage authorized security assessment projects and runs")
	fmt.Println("  schedule    Manage recurring assessment schedules and automated execution")
	fmt.Println("  history     View persistent execution history for assessments and schedules")
	fmt.Println("  diff        Compare assessment runs to identify finding deltas and regressions")
	fmt.Println("  notification Manage alerting, webhooks, and outbox notification delivery")
	fmt.Println("  operator    Launch local-first operator console for assessment and finding curation")
	fmt.Println("  config      Manage persistent CLI configuration settings")
	fmt.Println("  doctor      Diagnose environment, network stack, and permissions")
	fmt.Println("  version     Display Felix version and build environment")
	fmt.Println("  update      Check for or install verified updates from official releases")
	fmt.Println("  install     Install Felix binary to user system PATH")
	fmt.Println("  uninstall   Remove Felix binary from system PATH")
	fmt.Println("  completion  Generate shell autocompletion script")
	fmt.Println("  help        Show help for Felix or a specific command")
	fmt.Println("\nQuick Start:")
	fmt.Println("  felix scan https://example.com --export report.html --json scan.json")
	fmt.Println("  felix apk --analyze --report app.apk")
	fmt.Println("  felix client add --name \"Acme Corp\"")
	fmt.Println("  felix assessment create --client \"Acme Corp\" --name \"Q1 Audit\" --target https://example.com")
	fmt.Println("  felix assessment authorize <asm-ref> --authorizer \"Jane Doe\" --role \"CISO\"")
	fmt.Println("  felix assessment run <asm-ref>")
	fmt.Println("  felix assessment inventory <asm-ref>")
	fmt.Println("  felix report scan.json --html new_report.html")
	fmt.Println("  felix update --check")
	fmt.Println("  felix doctor")
	fmt.Println("  felix config show")
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
