package main

import (
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
	"felix/pkg/config"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// runScan executes the "felix scan" subcommand.
func runScan(args []string) int {
	cfgStore := config.Load()

	fs := flag.NewFlagSet("felix scan", flag.ContinueOnError)

	var (
		concurrency int
		timeoutSec  int
		maxSizeMB   int
		scopeMode   string
		userAgent   string
		inputFile   string
		verbose     bool
		silent      bool
		outPath     string
		htmlPath    string
		jsonPath    string
		exportPath  string
	)

	fs.IntVar(&concurrency, "c", cfgStore.Concurrency, "Number of concurrent workers")
	fs.IntVar(&timeoutSec, "t", cfgStore.Timeout, "HTTP timeout in seconds per target")
	fs.IntVar(&maxSizeMB, "max-size", cfgStore.MaxSizeMB, "Maximum asset size limit in MB")
	fs.StringVar(&scopeMode, "scope", cfgStore.Scope, "Crawl scope mode (same-origin, subdomains, explicit)")
	fs.StringVar(&userAgent, "user-agent", cfgStore.UserAgent, "User-Agent header string")
	fs.StringVar(&inputFile, "l", "", "Path to file containing target URLs (one per line)")
	fs.BoolVar(&verbose, "v", false, "Verbose output")
	fs.BoolVar(&verbose, "verbose", false, "Verbose output")
	fs.BoolVar(&silent, "s", false, "Silent / minimal output")
	fs.BoolVar(&silent, "silent", false, "Silent / minimal output")
	fs.StringVar(&outPath, "out", "", "Save raw reusable scan result JSON to file")
	fs.StringVar(&htmlPath, "html", "", "Export assessment report directly to HTML")
	fs.StringVar(&jsonPath, "json", "", "Export assessment report directly to JSON")
	fs.StringVar(&exportPath, "export", "", "Export report to file(s), comma-separated (e.g. report.html,report.json)")

	fs.Usage = func() {
		fmt.Println("Usage: felix scan [options] <target-url>")
		fmt.Println("\nExecute an automated security assessment against target web assets.")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
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
				case "c", "t", "max-size", "scope", "user-agent", "l", "out", "html", "json", "export":
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			clean := strings.TrimSpace(arg)
			if clean != "" && clean != "scan" {
				targets = append(targets, clean)
			}
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}

	for _, extra := range fs.Args() {
		clean := strings.TrimSpace(extra)
		if clean != "" && clean != "scan" {
			targets = append(targets, clean)
		}
	}

	if inputFile != "" {
		fileTargets, err := readLines(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read target file: %v\n", err)
			return 2
		}
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Error: no target URLs specified\n\n")
		fs.Usage()
		return 2
	}

	startTime := time.Now()

	if !silent {
		fmt.Print(banner)
		fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Timeout: %ds | Scope: %s\n\n",
			len(targets), concurrency, timeoutSec, scopeMode)
	}

	cConfig := crawler.Config{
		Concurrency:  concurrency,
		Timeout:      time.Duration(timeoutSec) * time.Second,
		MaxAssetSize: int64(maxSizeMB) * 1024 * 1024,
		ScopeMode:    crawler.ScopeMode(scopeMode),
		UserAgent:    userAgent,
	}
	c := crawler.New(cConfig)
	detector := secrets.NewDetector()
	cloudAuditor := cloud.NewDetector(nil)
	apiAuditor := api.NewDetector(nil)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := c.CrawlConcurrently(ctx, targets)

	totalDiscovered := 0
	totalEndpointsAudited := 0
	totalSecretFindings := 0
	totalCloudFindings := 0
	totalAPIFindings := 0
	var allReportFindings []report.Finding
	hasNetworkSuccess := false

	for res := range results {
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "[-] [%s] Error: %v\n\n", res.Target, res.Err)
			continue
		}
		hasNetworkSuccess = true

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

		if !silent {
			fmt.Printf("Target: %s\n\n", res.Target)
			fmt.Println("ASSET DISCOVERY")
			fmt.Println("────────────────────────────────────────")
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
		}

		// Secret Intelligence
		secretFindings := detector.ScanAssets(res.Assets)
		if !silent {
			fmt.Println("SECRET INTELLIGENCE")
			fmt.Println("────────────────────────────────────────")
			fmt.Printf("[+] Files analyzed: %d\n", filesAnalyzed)
			fmt.Printf("[+] Findings detected: %d\n", len(secretFindings))

			if len(secretFindings) > 0 {
				fmt.Println()
				fmt.Println("Findings:")
				for _, f := range secretFindings {
					fmt.Printf("  %-7s %s\n", f.Severity, f.Title)
					fmt.Printf("          %s:%d\n", f.FileOrigin, f.LineNumber)
					fmt.Printf("          Value: %s\n", f.Redacted)
					fmt.Printf("          Confidence: %s\n\n", f.Confidence)
					totalSecretFindings++
				}
			}
			fmt.Println()
		} else {
			totalSecretFindings += len(secretFindings)
		}

		// Cloud & BaaS Intelligence
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

		if !silent {
			fmt.Println("CLOUD & BaaS INTELLIGENCE")
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
		} else {
			totalCloudFindings += len(cloudResult.Findings)
		}

		// API Security Auditing
		apiResult := apiAuditor.Audit(ctx, res.Target, res.Assets)
		totalEndpointsAudited += apiResult.EndpointsScanned

		if !silent {
			fmt.Println("API SECURITY AUDITING")
			fmt.Println("────────────────────────────────────────")
			fmt.Printf("Endpoints audited: %d\n", apiResult.EndpointsScanned)
			if len(apiResult.DiscoveredEndpoints) > 0 {
				fmt.Printf("[+] Discovered endpoints: %d\n", len(apiResult.DiscoveredEndpoints))
			}
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
		} else {
			totalAPIFindings += len(apiResult.Findings)
		}

		// Aggregate Findings
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
			fmt.Println("Discovered Assets:")
			fmt.Println("────────────────────────────────────────")
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

	if !hasNetworkSuccess && len(targets) > 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to reach any target(s).\n")
		return 2
	}

	duration := time.Since(startTime)

	// Build unified assessment report
	rep := report.BuildMultiTargetReport(targets, allReportFindings)
	rep.Duration = duration.Round(time.Millisecond).String()
	rep.DurationMs = duration.Milliseconds()
	rep.RequestCount = totalDiscovered + totalEndpointsAudited

	var exported []string

	// Save reusable scan result if requested
	if outPath != "" {
		if err := report.WriteJSON(rep, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save scan result to %s: %v\n", outPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  Scan Result (JSON): %s", outPath))
	}

	// Export HTML if requested
	if htmlPath != "" {
		if err := report.WriteHTML(rep, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export HTML report to %s: %v\n", htmlPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  HTML Report:        %s", htmlPath))
	}

	// Export JSON if requested
	if jsonPath != "" {
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export JSON report to %s: %v\n", jsonPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  JSON Report:        %s", jsonPath))
	}

	// Backward compatibility: --export
	if exportPath != "" {
		files := strings.Split(exportPath, ",")
		for _, f := range files {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if strings.HasSuffix(strings.ToLower(f), ".html") {
				if err := report.WriteHTML(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export HTML to %s: %v\n", f, err)
				} else {
					exported = append(exported, fmt.Sprintf("  HTML Report:        %s", f))
				}
			} else {
				if err := report.WriteJSON(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export JSON to %s: %v\n", f, err)
				} else {
					exported = append(exported, fmt.Sprintf("  JSON Report:        %s", f))
				}
			}
		}
	}

	if !silent {
		printReportSummary(rep, verbose)

		if len(exported) > 0 {
			fmt.Println("Generated Reports:")
			for _, exp := range exported {
				fmt.Println(exp)
			}
			fmt.Println()
		}

		fmt.Printf("[*] Assessment complete in %s. %d asset(s) ingested, %d finding(s) discovered across %d target(s).\n",
			rep.Duration, totalDiscovered, len(rep.Findings), len(targets))
	}

	return determineExitCode(rep)
}
