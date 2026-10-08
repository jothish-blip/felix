package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
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

	var (
		timeoutStr     string
		concurrencyStr string
		scopeStr       string
		maxAssetsStr   string
		maxSizeStr     string
		exportStr      string
		jsonPath       string
		jsonBare       bool
		htmlStr        string
		outStr         string
		quiet          bool
		verbose        bool
		inputFile      string
		userAgent      string
		targets        []string
	)

	// Custom argument parser ensuring flag validation, clean order independence, and target extraction
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			printScanHelp()
			return 0
		}
		if arg == "--quiet" || arg == "-q" || arg == "--silent" || arg == "-s" {
			quiet = true
			continue
		}
		if arg == "--verbose" || arg == "-v" {
			verbose = true
			continue
		}

		// --timeout / -t
		if arg == "--timeout" || arg == "-t" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a duration argument (e.g. 10s, 30s, 1m)\n", arg)
				return 2
			}
			i++
			timeoutStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--timeout=") {
			timeoutStr = strings.TrimPrefix(arg, "--timeout=")
			continue
		}
		if strings.HasPrefix(arg, "-t=") {
			timeoutStr = strings.TrimPrefix(arg, "-t=")
			continue
		}

		// --concurrency / -c
		if arg == "--concurrency" || arg == "-c" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a positive integer argument\n", arg)
				return 2
			}
			i++
			concurrencyStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--concurrency=") {
			concurrencyStr = strings.TrimPrefix(arg, "--concurrency=")
			continue
		}
		if strings.HasPrefix(arg, "-c=") {
			concurrencyStr = strings.TrimPrefix(arg, "-c=")
			continue
		}

		// --scope
		if arg == "--scope" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --scope requires a mode argument (same-origin, subdomains, explicit)\n")
				return 2
			}
			i++
			scopeStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--scope=") {
			scopeStr = strings.TrimPrefix(arg, "--scope=")
			continue
		}

		// --max-assets
		if arg == "--max-assets" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --max-assets requires a positive integer argument\n")
				return 2
			}
			i++
			maxAssetsStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--max-assets=") {
			maxAssetsStr = strings.TrimPrefix(arg, "--max-assets=")
			continue
		}

		// --max-response-size / --max-size
		if arg == "--max-response-size" || arg == "--max-size" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a size argument (e.g. 5MB, 512KB)\n", arg)
				return 2
			}
			i++
			maxSizeStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--max-response-size=") {
			maxSizeStr = strings.TrimPrefix(arg, "--max-response-size=")
			continue
		}
		if strings.HasPrefix(arg, "--max-size=") {
			maxSizeStr = strings.TrimPrefix(arg, "--max-size=")
			continue
		}

		// --export
		if arg == "--export" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --export requires a file path argument (e.g. report.html)\n")
				return 2
			}
			i++
			exportStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--export=") {
			exportStr = strings.TrimPrefix(arg, "--export=")
			continue
		}

		// --html
		if arg == "--html" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --html requires a file path argument\n")
				return 2
			}
			i++
			htmlStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--html=") {
			htmlStr = strings.TrimPrefix(arg, "--html=")
			continue
		}

		// --out
		if arg == "--out" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --out requires a file path argument\n")
				return 2
			}
			i++
			outStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--out=") {
			outStr = strings.TrimPrefix(arg, "--out=")
			continue
		}

		// --json [optional file path]
		if arg == "--json" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(args[i+1], "://") && (strings.HasSuffix(strings.ToLower(args[i+1]), ".json") || !strings.Contains(args[i+1], ".")) {
				i++
				jsonPath = args[i]
			} else {
				jsonBare = true
				jsonPath = "scan-result.json"
			}
			continue
		}
		if strings.HasPrefix(arg, "--json=") {
			jsonPath = strings.TrimPrefix(arg, "--json=")
			continue
		}

		// -l <targets file>
		if arg == "-l" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: -l requires a file path argument\n")
				return 2
			}
			i++
			inputFile = args[i]
			continue
		}
		if strings.HasPrefix(arg, "-l=") {
			inputFile = strings.TrimPrefix(arg, "-l=")
			continue
		}

		// --user-agent
		if arg == "--user-agent" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --user-agent requires an argument\n")
				return 2
			}
			i++
			userAgent = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--user-agent=") {
			userAgent = strings.TrimPrefix(arg, "--user-agent=")
			continue
		}

		// Unknown flag
		if strings.HasPrefix(arg, "-") {
			fmt.Fprintf(os.Stderr, "[-] error: unknown flag %q\n\n", arg)
			printScanHelp()
			return 2
		}

		// Non-flag argument (Target URL)
		clean := strings.TrimSpace(arg)
		if clean != "" && clean != "scan" {
			targets = append(targets, clean)
		}
	}

	// 1. Conflict Check: --quiet and --verbose cannot be combined
	if quiet && verbose {
		fmt.Fprintf(os.Stderr, "[-] error: --quiet and --verbose cannot be used together\n")
		return 2
	}

	// 2. Timeout Validation
	timeoutDuration := time.Duration(cfgStore.Timeout) * time.Second
	if timeoutStr != "" {
		d, err := parseTimeout(timeoutStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
			return 2
		}
		timeoutDuration = d
	}

	// 3. Concurrency Validation
	concurrencyVal := cfgStore.Concurrency
	if concurrencyStr != "" {
		val, err := strconv.Atoi(concurrencyStr)
		if err != nil || val <= 0 {
			fmt.Fprintf(os.Stderr, "[-] error: invalid concurrency %q: must be a positive integer\n", concurrencyStr)
			return 2
		}
		concurrencyVal = val
	}

	// 4. Scope Validation
	scopeMode := crawler.ScopeMode(cfgStore.Scope)
	if scopeStr != "" {
		sm, err := validateScope(scopeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
			return 2
		}
		scopeMode = sm
	}

	// 5. Max Assets Validation
	maxAssetsVal := 0
	if maxAssetsStr != "" {
		val, err := strconv.Atoi(maxAssetsStr)
		if err != nil || val <= 0 {
			fmt.Fprintf(os.Stderr, "[-] error: invalid max-assets %q: must be a positive integer\n", maxAssetsStr)
			return 2
		}
		maxAssetsVal = val
	}

	// 6. Max Response Size Validation
	maxSizeBytes := int64(cfgStore.MaxSizeMB) * 1024 * 1024
	if maxSizeStr != "" {
		sz, err := parseResponseSize(maxSizeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] error: %v\n", err)
			return 2
		}
		maxSizeBytes = sz
	}

	// 7. User Agent
	if userAgent == "" {
		userAgent = cfgStore.UserAgent
	}

	// 8. Read targets from input file if supplied
	if inputFile != "" {
		fileTargets, err := readLines(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read target file: %v\n", err)
			return 2
		}
		targets = append(targets, fileTargets...)
	}

	// 9. Ensure at least one target is specified
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Error: no target URLs specified\n\n")
		printScanHelp()
		return 2
	}

	startTime := time.Now()

	// Operational Banners / Status
	if !quiet {
		if !jsonBare {
			fmt.Print(banner)
		}
		if verbose {
			fmt.Printf("[*] Active Scan Configuration:\n")
			fmt.Printf("    Targets:          %d\n", len(targets))
			fmt.Printf("    Concurrency:      %d workers\n", concurrencyVal)
			fmt.Printf("    Timeout:          %s\n", timeoutDuration)
			fmt.Printf("    Scope:            %s\n", scopeMode)
			if maxAssetsVal > 0 {
				fmt.Printf("    Max Assets:       %d\n", maxAssetsVal)
			} else {
				fmt.Printf("    Max Assets:       unbounded\n")
			}
			fmt.Printf("    Max Size:         %d bytes (%s)\n", maxSizeBytes, formatBytes(maxSizeBytes))
			fmt.Printf("    User-Agent:       %s\n\n", userAgent)
		} else if !jsonBare {
			fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Timeout: %s | Scope: %s\n\n",
				len(targets), concurrencyVal, timeoutDuration, scopeMode)
		}
	}

	// Initialize Crawler & Security Analyzers with validated configuration
	cConfig := crawler.Config{
		Concurrency:  concurrencyVal,
		Timeout:      timeoutDuration,
		MaxAssetSize: maxSizeBytes,
		MaxAssets:    maxAssetsVal,
		ScopeMode:    scopeMode,
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

		if !quiet && !jsonBare {
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
		if !quiet && !jsonBare {
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

		if !quiet && !jsonBare {
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

		if !quiet && !jsonBare {
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

		// Aggregate Findings into unified reporting model
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
			fmt.Println("Discovered Assets Inventory:")
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
		fmt.Fprintf(os.Stderr, "[-] Failed to reach target(s).\n")
		return 2
	}

	duration := time.Since(startTime)

	// Build unified assessment report from the single scan execution
	rep := report.BuildMultiTargetReport(targets, allReportFindings)
	rep.Duration = duration.Round(time.Millisecond).String()
	rep.DurationMs = duration.Milliseconds()
	rep.RequestCount = totalDiscovered + totalEndpointsAudited

	var exported []string

	// 1. Export JSON scan result if requested
	if outStr != "" {
		if err := report.WriteJSON(rep, outStr); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save scan result to %s: %v\n", outStr, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  Scan Result (JSON): %s", outStr))
	}
	if jsonPath != "" {
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export JSON report to %s: %v\n", jsonPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  JSON Report:        %s", jsonPath))
	}

	// 2. Export HTML if requested via --html
	if htmlStr != "" {
		if err := report.WriteHTML(rep, htmlStr); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export HTML report to %s: %v\n", htmlStr, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  HTML Report:        %s", htmlStr))
	}

	// 3. Export via canonical --export flag (single or comma-separated HTML/JSON)
	if exportStr != "" {
		files := strings.Split(exportStr, ",")
		for _, f := range files {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if strings.HasSuffix(strings.ToLower(f), ".html") {
				if err := report.WriteHTML(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export HTML to %s: %v\n", f, err)
					return 2
				}
				exported = append(exported, fmt.Sprintf("  HTML Report:        %s", f))
			} else {
				if err := report.WriteJSON(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export JSON to %s: %v\n", f, err)
					return 2
				}
				exported = append(exported, fmt.Sprintf("  JSON Report:        %s", f))
			}
		}
	}

	// Bare --json: Output valid machine-readable JSON directly
	if jsonBare {
		jsonBytes, err := report.GenerateJSON(rep)
		if err == nil {
			fmt.Println(string(jsonBytes))
		}
	} else if !quiet {
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

func printScanHelp() {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  felix scan [options] <target-url>")
	fmt.Println("\nExecute an automated security assessment against target web assets.")
	fmt.Println("\nOptions:")
	fmt.Println("  --timeout <duration>        Network timeout per target (e.g. 10s, 30s, 1m) [default: 10s]")
	fmt.Println("  --concurrency <int>         Number of concurrent workers [default: 10]")
	fmt.Println("  --scope <mode>              Crawl scope mode (same-origin, subdomains, explicit) [default: same-origin]")
	fmt.Println("  --max-assets <int>          Maximum number of assets to process/discover")
	fmt.Println("  --max-response-size <size>  Maximum asset response size (e.g. 10MB, 512KB) [default: 10MB]")
	fmt.Println("  --export <file>             Export assessment report to HTML or JSON file")
	fmt.Println("  --json [file]               Save machine-readable scan result as JSON (or output to stdout)")
	fmt.Println("  --quiet, -q                 Suppress normal terminal output and banners")
	fmt.Println("  --verbose, -v               Enable detailed operational output")
	fmt.Println("  -l <file>                   Path to file containing target URLs (one per line)")
	fmt.Println("  --user-agent <string>       Custom User-Agent header string")
}

func parseTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty timeout value")
	}
	d, err := time.ParseDuration(s)
	if err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("timeout must be positive: %q", s)
		}
		return d, nil
	}
	if sec, errInt := strconv.Atoi(s); errInt == nil {
		if sec <= 0 {
			return 0, fmt.Errorf("timeout must be positive: %q", s)
		}
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid timeout format: %q (use e.g. 10s, 30s, 1m)", s)
}

func parseResponseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size value")
	}
	upper := strings.ToUpper(s)
	var multiplier int64 = 1
	numStr := upper

	if strings.HasSuffix(upper, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(upper, "GB")
	} else if strings.HasSuffix(upper, "G") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(upper, "G")
	} else if strings.HasSuffix(upper, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(upper, "MB")
	} else if strings.HasSuffix(upper, "M") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(upper, "M")
	} else if strings.HasSuffix(upper, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(upper, "KB")
	} else if strings.HasSuffix(upper, "K") {
		multiplier = 1024
		numStr = strings.TrimSuffix(upper, "K")
	} else if strings.HasSuffix(upper, "B") {
		multiplier = 1
		numStr = strings.TrimSuffix(upper, "B")
	}

	numStr = strings.TrimSpace(numStr)
	val, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %q (use e.g. 10MB, 512KB)", s)
	}
	if val <= 0 {
		return 0, fmt.Errorf("max-response-size must be positive: %q", s)
	}
	return val * multiplier, nil
}

func validateScope(s string) (crawler.ScopeMode, error) {
	mode := strings.ToLower(strings.TrimSpace(s))
	switch crawler.ScopeMode(mode) {
	case crawler.ScopeSameOrigin, crawler.ScopeSubdomains, crawler.ScopeExplicit:
		return crawler.ScopeMode(mode), nil
	default:
		return "", fmt.Errorf("unsupported scope %q; supported modes: same-origin, subdomains, explicit", s)
	}
}

func formatBytes(b int64) string {
	if b >= 1024*1024*1024 {
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	}
	if b >= 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	}
	if b >= 1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%dB", b)
}
