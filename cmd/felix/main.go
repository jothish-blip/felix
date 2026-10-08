package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

const banner = `
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================
`

func main() {
	var (
		concurrency int
		timeoutSec  int
		maxSizeMB   int
		scopeMode   string
		userAgent   string
		inputFile   string
		verbose     bool
		exportPath  string
	)

	fs := flag.NewFlagSet("felix", flag.ExitOnError)
	fs.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	fs.IntVar(&timeoutSec, "t", 10, "HTTP timeout in seconds per target")
	fs.IntVar(&maxSizeMB, "max-size", 10, "Maximum asset size limit in MB")
	fs.StringVar(&scopeMode, "scope", string(crawler.ScopeSameOrigin), "Crawl scope mode (same-origin, subdomains, explicit)")
	fs.StringVar(&userAgent, "user-agent", crawler.DefaultUserAgent, "User-Agent header string")
	fs.StringVar(&inputFile, "l", "", "Path to file containing target URLs (one per line)")
	fs.BoolVar(&verbose, "v", false, "Enable verbose output")
	fs.StringVar(&exportPath, "export", "", "Export report to file (e.g. report.json or report.html)")

	fs.Usage = func() {
		fmt.Print(banner)
		fmt.Printf("Usage: felix scan [options] <target-url>\n       felix [options] <target-url>\n\nOptions:\n")
		fs.PrintDefaults()
	}

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "scan" {
		args = args[1:]
	}

	var flagArgs []string
	var targets []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "c", "t", "max-size", "scope", "user-agent", "l", "export":
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			if arg != "scan" && strings.TrimSpace(arg) != "" {
				targets = append(targets, strings.TrimSpace(arg))
			}
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	for _, extra := range fs.Args() {
		if extra != "scan" && strings.TrimSpace(extra) != "" {
			targets = append(targets, strings.TrimSpace(extra))
		}
	}

	if inputFile != "" {
		fileTargets, err := readLines(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read target file: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	fmt.Print(banner)
	fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Timeout: %ds | Scope: %s\n\n",
		len(targets), concurrency, timeoutSec, scopeMode)

	cfg := crawler.Config{
		Concurrency:  concurrency,
		Timeout:      time.Duration(timeoutSec) * time.Second,
		MaxAssetSize: int64(maxSizeMB) * 1024 * 1024,
		ScopeMode:    crawler.ScopeMode(scopeMode),
		UserAgent:    userAgent,
	}
	c := crawler.New(cfg)
	detector := secrets.NewDetector()
	cloudAuditor := cloud.NewDetector(nil)
	apiAuditor := api.NewDetector(nil)

	// Graceful cancellation on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := c.CrawlConcurrently(ctx, targets)

	totalDiscovered := 0
	totalSecretFindings := 0
	totalCloudFindings := 0
	totalAPIFindings := 0
	var allReportFindings []report.Finding

	for res := range results {
		if res.Err != nil {
			fmt.Printf("[-] [%s] Error: %v\n\n", res.Target, res.Err)
			continue
		}

		jsCount := 0
		cssCount := 0
		mapCount := 0
		manifestCount := 0
		filesAnalyzed := 0

		for _, a := range res.Assets {
			switch a.Type {
			case crawler.AssetJavaScript:
				jsCount++
			case crawler.AssetStylesheet:
				cssCount++
			case crawler.AssetSourceMap:
				mapCount++
			case crawler.AssetManifest:
				manifestCount++
			}
			if len(a.Content) > 0 {
				filesAnalyzed++
			}
		}

		fmt.Printf("Target: %s\n\n", res.Target)
		fmt.Println("ENGINE 1 — ASSET INGESTION")
		fmt.Printf("[+] Assets discovered: %d\n", len(res.Assets))
		if jsCount > 0 {
			fmt.Printf("[+] JavaScript: %d\n", jsCount)
		}
		if cssCount > 0 {
			fmt.Printf("[+] Stylesheets: %d\n", cssCount)
		}
		if mapCount > 0 {
			fmt.Printf("[+] Source maps: %d\n", mapCount)
		}
		if manifestCount > 0 {
			fmt.Printf("[+] Manifests: %d\n", manifestCount)
		}
		fmt.Println()

		// Run Engine 2 Secret Detection
		secretFindings := detector.ScanAssets(res.Assets)

		fmt.Println("ENGINE 2 — SECRET INTELLIGENCE")
		fmt.Printf("[+] Files analyzed: %d\n", filesAnalyzed)
		fmt.Printf("[+] Confirmed findings: %d\n", len(secretFindings))

		if len(secretFindings) > 0 {
			fmt.Println()
			fmt.Println("Findings")
			fmt.Println("────────────────────────────────────")
			for _, f := range secretFindings {
				fmt.Printf("%-7s %s\n", f.Severity, f.Title)
				fmt.Printf("        %s:%d\n", f.FileOrigin, f.LineNumber)
				fmt.Printf("        Value: %s\n", f.Redacted)
				fmt.Printf("        Confidence: %s\n\n", f.Confidence)
				totalSecretFindings++
			}
		}
		fmt.Println()

		// Run Engine 3 Cloud Intelligence
		cloudResult := cloudAuditor.Audit(ctx, res.Assets, secretFindings)

		sbCount, fbCount, awsCount, gcpCount := 0, 0, 0, 0
		for _, s := range cloudResult.Services {
			switch s.Provider {
			case cloud.ProviderSupabase:
				sbCount++
			case cloud.ProviderFirebase:
				fbCount++
			case cloud.ProviderAWS:
				awsCount++
			case cloud.ProviderGCP:
				gcpCount++
			}
		}

		fmt.Println("ENGINE 3 — CLOUD & BaaS INTELLIGENCE")
		fmt.Println("────────────────────────────────────────")
		fmt.Println("Providers discovered:")
		fmt.Printf("  Supabase: %d\n", sbCount)
		fmt.Printf("  Firebase: %d\n", fbCount)
		fmt.Printf("  AWS:      %d\n", awsCount)
		fmt.Printf("  GCP:      %d\n", gcpCount)
		fmt.Println()

		if len(cloudResult.Findings) > 0 {
			fmt.Println("Findings:")
			for _, f := range cloudResult.Findings {
				fmt.Printf("  %-6s %s\n", f.Severity, f.Description)
				fmt.Printf("         Endpoint: %s\n", f.Endpoint)
				fmt.Printf("         Confidence: %s\n\n", f.Confidence)
				totalCloudFindings++
			}
		}

		// Run Engine 4 Modern API & Endpoint Intelligence
		apiResult := apiAuditor.Audit(ctx, res.Target, res.Assets)

		fmt.Println("ENGINE 4 — MODERN API & ENDPOINT INTELLIGENCE")
		fmt.Println("────────────────────────────────────────")
		fmt.Printf("Endpoints audited: %d\n", apiResult.EndpointsScanned)
		fmt.Printf("[+] GraphQL endpoints:     %d\n", apiResult.GraphQLCount)
		fmt.Printf("[+] Sensitive endpoints:   %d\n", apiResult.SensitiveCount)
		fmt.Printf("[+] CORS observations:     %d\n", apiResult.CORSCount)
		fmt.Printf("[+] Security header checks: %d\n\n", apiResult.HeaderCount)

		if len(apiResult.Findings) > 0 {
			fmt.Println("Findings:")
			for _, f := range apiResult.Findings {
				fmt.Printf("  %-7s [%s] %s\n", f.Severity, f.Category, f.Description)
				fmt.Printf("          Endpoint: %s (%s)\n", f.Endpoint, f.Method)
				if f.Evidence != "" {
					fmt.Printf("          Evidence: %s\n", api.RedactEvidence(f.Evidence))
				}
				fmt.Printf("          Confidence: %s\n\n", f.Confidence)
				totalAPIFindings++
			}
		}

		// Aggregate into Engine 5 unified model
		for _, a := range res.Assets {
			if f, ok := report.FromCrawlerAsset(res.Target, a); ok {
				allReportFindings = append(allReportFindings, f)
			}
		}
		for _, f := range secretFindings {
			allReportFindings = append(allReportFindings, report.FromSecretFinding(res.Target, f))
		}
		for _, f := range cloudResult.Findings {
			allReportFindings = append(allReportFindings, report.FromCloudFinding(res.Target, f))
		}
		for _, f := range apiResult.Findings {
			allReportFindings = append(allReportFindings, report.FromAPIFinding(res.Target, f))
		}

		if verbose && len(res.Assets) > 0 {
			fmt.Println("Assets")
			fmt.Println("────────────────────────────────────")
			for _, a := range res.Assets {
				label := assetLabel(a.Type)
				statusSuffix := ""
				if a.Error != nil {
					statusSuffix = fmt.Sprintf(" [%v]", a.Error)
				} else if !a.InScope {
					statusSuffix = " [external / skipped]"
				}
				fmt.Printf("%-8s %s%s\n", label, a.URL, statusSuffix)
			}
			fmt.Println()
		}

		totalDiscovered += len(res.Assets)
	}

	// Engine 5: Finding Correlation, Risk Scoring & Reporting
	rep := report.BuildMultiTargetReport(targets, allReportFindings)

	fmt.Println("===========================================================")
	fmt.Println(" FELIX :: WEB SECURITY AUDITING REPORT")
	fmt.Println("===========================================================")
	if len(targets) == 1 {
		fmt.Printf("Target:\n%s\n\n", targets[0])
	} else {
		fmt.Printf("Targets (%d):\n%s\n\n", len(targets), strings.Join(targets, "\n"))
	}
	fmt.Println("Scan completed.")
	fmt.Printf("\nRisk Score: %d/100\n", rep.RiskScore)
	fmt.Printf("Risk Level: %s\n\n", rep.RiskLevel)

	fmt.Println("Findings:")
	fmt.Printf("  CRITICAL  %d\n", rep.Summary.CriticalCount)
	fmt.Printf("  HIGH      %d\n", rep.Summary.HighCount)
	fmt.Printf("  MEDIUM    %d\n", rep.Summary.MediumCount)
	fmt.Printf("  LOW       %d\n", rep.Summary.LowCount)
	fmt.Printf("  INFO      %d\n\n", rep.Summary.InfoCount)

	if len(rep.SecurityStories) > 0 {
		fmt.Printf("CORRELATED SECURITY STORIES (%d)\n", len(rep.SecurityStories))
		fmt.Println("────────────────────────────────────────")
		for _, s := range rep.SecurityStories {
			fmt.Printf("[%s] %s\n", s.Severity, s.Title)
			fmt.Printf("  Impact:      %s\n", s.Impact)
			fmt.Printf("  Remediation: %s\n\n", s.Remediation)
		}
	}

	if len(rep.TopPriorities) > 0 {
		fmt.Println("TOP PRIORITIES")
		fmt.Println("────────────────────────────────────────")
		for _, p := range rep.TopPriorities {
			fmt.Printf("[%s] %s\n", p.Severity, p.Title)
			fmt.Printf("Confidence: %s\n", p.Confidence)
			fmt.Printf("Endpoint:   %s (%s)\n", p.Endpoint, p.Method)
			if p.Remediation != "" {
				fmt.Printf("Action:     %s\n", p.Remediation)
			}
			fmt.Println()
		}
	}

	if exportPath != "" {
		files := strings.Split(exportPath, ",")
		var exported []string
		for _, f := range files {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if strings.HasSuffix(strings.ToLower(f), ".html") {
				if err := report.WriteHTML(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export HTML to %s: %v\n", f, err)
				} else {
					exported = append(exported, fmt.Sprintf("  HTML: %s", f))
				}
			} else {
				// Default to JSON
				if err := report.WriteJSON(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export JSON to %s: %v\n", f, err)
				} else {
					exported = append(exported, fmt.Sprintf("  JSON: %s", f))
				}
			}
		}
		if len(exported) > 0 {
			fmt.Println("Reports:")
			for _, exp := range exported {
				fmt.Println(exp)
			}
			fmt.Println()
		}
	}

	fmt.Printf("[*] Scan complete. %d asset(s) ingested, %d secret, %d cloud, %d API finding(s) discovered across %d target(s).\n",
		totalDiscovered, totalSecretFindings, totalCloudFindings, totalAPIFindings, len(targets))
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
