package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"felix/pkg/crawler"
)

const banner = `
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================
`

func main() {
	if len(os.Args) < 2 {
		printRootHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]

	switch cmd {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "report":
		os.Exit(runReport(os.Args[2:]))
	case "config":
		os.Exit(runConfig(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "version", "--version", "-V":
		os.Exit(runVersion(os.Args[2:]))
	case "install":
		os.Exit(runInstall(os.Args[2:]))
	case "uninstall":
		os.Exit(runUninstall(os.Args[2:]))
	case "completion":
		os.Exit(runCompletion(os.Args[2:]))
	case "help", "--help", "-h":
		if len(os.Args) > 2 {
			sub := os.Args[2]
			switch sub {
			case "scan":
				os.Exit(runScan([]string{"--help"}))
			case "report":
				os.Exit(runReport([]string{"--help"}))
			case "config":
				os.Exit(runConfig([]string{"--help"}))
			case "doctor":
				os.Exit(runDoctor([]string{"--help"}))
			case "completion":
				os.Exit(runCompletion([]string{"--help"}))
			default:
				printRootHelp()
				os.Exit(0)
			}
		}
		printRootHelp()
		os.Exit(0)
	default:
		// If argument starts with '-' or looks like a URL/target, treat as 'scan' for convenience
		if strings.HasPrefix(cmd, "-") || strings.Contains(cmd, "://") || strings.Contains(cmd, ".") {
			os.Exit(runScan(os.Args[1:]))
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown command: %s\n\n", cmd)
		printRootHelp()
		os.Exit(2)
	}
}

func printRootHelp() {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  felix <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  scan        Audit target web applications for security exposures")
	fmt.Println("  report      Generate assessment reports from existing scan results (zero network)")
	fmt.Println("  config      Manage persistent CLI configuration settings")
	fmt.Println("  doctor      Diagnose environment, network stack, and permissions")
	fmt.Println("  version     Display Felix version and build environment")
	fmt.Println("  install     Install Felix binary to user system PATH")
	fmt.Println("  uninstall   Remove Felix binary from system PATH")
	fmt.Println("  completion  Generate shell autocompletion script")
	fmt.Println("  help        Show help for Felix or a specific command")
	fmt.Println("\nQuick Start:")
	fmt.Println("  felix scan https://example.com --out scan.json --html report.html")
	fmt.Println("  felix report scan.json --html new_report.html")
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
