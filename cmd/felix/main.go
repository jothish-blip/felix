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
	)

	fs := flag.NewFlagSet("felix", flag.ExitOnError)
	fs.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	fs.IntVar(&timeoutSec, "t", 10, "HTTP timeout in seconds per target")
	fs.IntVar(&maxSizeMB, "max-size", 10, "Maximum asset size limit in MB")
	fs.StringVar(&scopeMode, "scope", string(crawler.ScopeSameOrigin), "Crawl scope mode (same-origin, subdomains, explicit)")
	fs.StringVar(&userAgent, "user-agent", crawler.DefaultUserAgent, "User-Agent header string")
	fs.StringVar(&inputFile, "l", "", "Path to file containing target URLs (one per line)")
	fs.BoolVar(&verbose, "v", false, "Enable verbose output")

	fs.Usage = func() {
		fmt.Print(banner)
		fmt.Printf("Usage: felix scan [options] <target-url>\n       felix [options] <target-url>\n\nOptions:\n")
		fs.PrintDefaults()
	}

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "scan" {
		args = args[1:]
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	var targets []string
	for _, arg := range fs.Args() {
		if arg != "scan" && strings.TrimSpace(arg) != "" {
			targets = append(targets, strings.TrimSpace(arg))
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
