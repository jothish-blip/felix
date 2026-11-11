package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/discovery"
)

// runRecon executes the "felix recon" subcommand.
func runRecon(args []string) int {
	var (
		targetURL     string
		timeoutSec    int = 15
		concurrency   int = 5
		maxAssets     int = 200
		allowLoopback bool
		allowPrivate  bool
		jsonOutput    bool
		outputPath    string
		verbose       bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--target" || arg == "-t":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		case arg == "--timeout":
			if i+1 < len(args) {
				if t, err := time.ParseDuration(args[i+1]); err == nil {
					timeoutSec = int(t.Seconds())
				} else {
					fmt.Sscanf(args[i+1], "%d", &timeoutSec)
				}
				i++
			}
		case arg == "--concurrency" || arg == "-c":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &concurrency)
				i++
			}
		case arg == "--max-assets":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxAssets)
				i++
			}
		case arg == "--allow-loopback":
			allowLoopback = true
		case arg == "--allow-private":
			allowPrivate = true
		case arg == "--output" || arg == "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printReconHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && targetURL == "" {
				targetURL = arg
			}
		}
	}

	if targetURL == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: target URL is required (use --target <url> or pass as first argument)\n\n")
		printReconHelp()
		return 2
	}

	// Normalize URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		if strings.HasPrefix(targetURL, "localhost") || strings.HasPrefix(targetURL, "127.0.0.1") {
			targetURL = "http://" + targetURL
		} else {
			targetURL = "https://" + targetURL
		}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: invalid target URL %q\n", targetURL)
		return 2
	}

	host := parsed.Hostname()
	ips, _ := net.LookupIP(host)
	if len(ips) > 0 {
		for _, ip := range ips {
			if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true", allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true"); prohibited {
				fmt.Fprintf(os.Stderr, "[-] Error: target %s resolves to prohibited address (%s: %s). Use --allow-loopback or --allow-private to permit.\n", targetURL, ip.String(), reason)
				return 2
			}
		}
	}

	// Fetch initial target page
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: crawler.NewSafeDialContext(crawler.SafeDialerOptions{
			Timeout:         time.Duration(timeoutSec) * time.Second,
			AllowLoopback:   allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true",
			AllowPrivateIPs: allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true",
		}),
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error creating request: %v\n", err)
		return 1
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Felix-Recon/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Target unreachable: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	htmlBody := string(bodyBytes)

	// Extract TLS certs
	var certs []*tls.Certificate
	_ = certs

	// Run discovery engine
	engineCfg := discovery.Config{
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		MaxAssets:   maxAssets,
	}
	engine := discovery.NewEngine(engineCfg)

	scopeAllowed := func(u string) bool {
		p, err := url.Parse(u)
		if err != nil {
			return false
		}
		return strings.EqualFold(p.Hostname(), host) || strings.HasSuffix(strings.ToLower(p.Hostname()), "."+strings.ToLower(host))
	}

	inv := engine.AnalyzeTarget(
		context.Background(),
		"recon-asm", "recon-exec", "recon-target", targetURL,
		htmlBody, resp.Header, nil, nil, scopeAllowed,
	)

	summary := inv.Summary()

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"target":      targetURL,
			"status_code": resp.StatusCode,
			"headers":     resp.Header,
			"inventory":   inv,
			"summary":     summary,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[-] JSON error: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 ATTACK-SURFACE RECONNAISSANCE")
	fmt.Println("===========================================================")
	fmt.Printf("  Target URL:       %s\n", targetURL)
	fmt.Printf("  HTTP Status:      %d %s\n", resp.StatusCode, resp.Status)
	fmt.Printf("  Server Header:    %s\n", resp.Header.Get("Server"))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		fmt.Printf("  Content-Type:     %s\n", ct)
	}
	fmt.Println("-----------------------------------------------------------")
	fmt.Println("Discovered Attack Surfaces:")
	fmt.Printf("  - Total Assets:         %d\n", summary.TotalAssets)
	fmt.Printf("  - Endpoints:            %d\n", summary.EndpointsCount)
	fmt.Printf("  - Forms:                %d\n", summary.FormsCount)
	fmt.Printf("  - Parameters:           %d\n", summary.ParametersCount)
	fmt.Printf("  - Auth Surfaces:        %d\n", summary.AuthSurfacesCount)
	fmt.Printf("  - Discovered Hosts:     %d\n", summary.HostsCount)
	fmt.Printf("  - Storage / Buckets:    %d\n", summary.StorageCount)
	fmt.Printf("  - Associated Relations: %d\n", summary.TotalRelations)
	fmt.Println("===========================================================")

	if verbose {
		fmt.Println("\nIdentified Endpoints & Routes:")
		count := 0
		for _, a := range inv.Assets {
			if a.Type == discovery.AssetTypeEndpoint || a.Type == discovery.AssetTypeForm {
				count++
				fmt.Printf("  [%s] %s\n", a.Type, a.DisplayName)
				if count >= 30 {
					fmt.Printf("  ... and %d more assets (use --json for full list)\n", len(inv.Assets)-30)
					break
				}
			}
		}
	}

	if outputPath != "" {
		data, err := json.MarshalIndent(map[string]any{
			"target":    targetURL,
			"inventory": inv,
			"summary":   summary,
		}, "", "  ")
		if err == nil {
			_ = os.WriteFile(outputPath, data, 0644)
			fmt.Printf("\n[+] Reconnaissance inventory exported to: %s\n", outputPath)
		}
	}

	return 0
}

func printReconHelp() {
	fmt.Println("Usage: felix recon --target <url> [flags]")
	fmt.Println("\nPerform automated zero-credential attack-surface and asset discovery.")
	fmt.Println("\nFlags:")
	fmt.Println("  --target, -t <url>       Target application URL (required)")
	fmt.Println("  --timeout <duration>     HTTP request timeout (default: 15s)")
	fmt.Println("  --concurrency, -c <n>    Concurrent discovery workers (default: 5)")
	fmt.Println("  --max-assets <n>         Maximum assets to discover (default: 200)")
	fmt.Println("  --output, -o <file>      Export discovered inventory to JSON file")
	fmt.Println("  --json                   Output complete inventory structure as JSON")
	fmt.Println("  --allow-loopback         Allow testing against loopback/localhost (testing only)")
	fmt.Println("  --allow-private          Allow testing against RFC 1918 private IPs")
	fmt.Println("  --verbose, -v            Show full list of discovered routes and forms")
	fmt.Println("  --help, -h               Show this help message")
}
