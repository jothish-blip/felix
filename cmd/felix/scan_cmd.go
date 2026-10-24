package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"felix/pkg/api"
	"felix/pkg/clierror"
	"felix/pkg/cloud"
	"felix/pkg/config"
	"felix/pkg/crawler"
	"felix/pkg/policy"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/ui"
)

// isAPKScan detects if the command arguments specify an Android APK target rather than a web URL.
func isAPKScan(args []string) (string, bool) {
	skipNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--export" || arg == "-e" || arg == "--output" || arg == "-o" ||
			arg == "--report" || arg == "--html" || arg == "--out" ||
			arg == "--json" || arg == "--sarif" ||
			arg == "--timeout" || arg == "-t" || arg == "--concurrency" || arg == "-c" ||
			arg == "--rate-limit" || arg == "-r" || arg == "--rate" || arg == "--scope" ||
			arg == "--max-assets" || arg == "--max-size" || arg == "--max-response-size" ||
			arg == "-l" || arg == "--policy" || arg == "--user-agent" ||
			arg == "-i" || arg == "--input-file" || arg == "--targets-file" || arg == "--file" ||
			arg == "--spec" || arg == "--profile" || arg == "--webhook" ||
			arg == "--notify-provider" || arg == "--notify-secret" ||
			arg == "--notify-min-severity" || arg == "--notify-previous-secret" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				skipNext = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		trimmed := strings.TrimSpace(arg)
		if trimmed != "" && trimmed != "scan" && !strings.Contains(trimmed, "://") && strings.HasSuffix(strings.ToLower(trimmed), ".apk") {
			return trimmed, true
		}
	}
	return "", false
}

// runScan executes the "felix scan" subcommand.
func runScan(args []string) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			printScanHelp()
			return 0
		}
	}

	if apkTarget, ok := isAPKScan(args); ok && apkTarget != "" {
		apkArgs := make([]string, 0, len(args)+1)
		hasAnalyze := false
		for _, x := range args {
			if x == "--analyze" || x == "--analyze-manifest" || x == "--analyze-artifacts" || x == "--assess" || x == "--handoff" {
				hasAnalyze = true
			}
			apkArgs = append(apkArgs, x)
		}
		if !hasAnalyze {
			apkArgs = append([]string{"--analyze"}, apkArgs...)
		}
		return runAPK(apkArgs)
	}

	cfgStore, err := config.LoadWithEnv("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] configuration error: %v\n", err)
		return 2
	}

	var (
		timeoutStr     string
		concurrencyStr string
		rateLimitStr   string
		scopeStr       string
		maxAssetsStr   string
		maxSizeStr     string
		exportStr      string
		jsonPath       string
		jsonBare       bool
		htmlStr        string
		outStr         string
		sarifPath      string
		policyPath     string
		quiet          bool
		verbose        bool
		inputFile      string
		userAgent      string
		allowPrivate   = cfgStore.AllowPrivateIPs
		allowLoopback  = cfgStore.AllowLoopback
		insecure       = cfgStore.InsecureSkipVerify
		activeVerif    = cfgStore.ActiveVerification
		notifyEnabled  = cfgStore.Notification.Enabled
		notifyExplicit bool
		webhookFlagURL string
		notifyProvider       string
		notifySecret         string
		notifyPreviousSecret string
		notifyRequireSigning bool
		notifyMinSev         string
		specPath             string
		probeLive            bool
		profilePath          string
		crossTenant          bool
		targets              []string
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

		// --rate-limit / -r / --rate
		if arg == "--rate-limit" || arg == "-r" || arg == "--rate" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a positive number (requests per second)\n", arg)
				return 2
			}
			i++
			rateLimitStr = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--rate-limit=") {
			rateLimitStr = strings.TrimPrefix(arg, "--rate-limit=")
			continue
		}
		if strings.HasPrefix(arg, "-r=") {
			rateLimitStr = strings.TrimPrefix(arg, "-r=")
			continue
		}
		if strings.HasPrefix(arg, "--rate=") {
			rateLimitStr = strings.TrimPrefix(arg, "--rate=")
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

		// --sarif [optional file path]
		if arg == "--sarif" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(args[i+1], "://") && (strings.HasSuffix(strings.ToLower(args[i+1]), ".sarif") || strings.HasSuffix(strings.ToLower(args[i+1]), ".json")) {
				i++
				sarifPath = args[i]
			} else {
				sarifPath = "scan-result.sarif"
			}
			continue
		}
		if strings.HasPrefix(arg, "--sarif=") {
			sarifPath = strings.TrimPrefix(arg, "--sarif=")
			continue
		}

		// --policy [file path]
		if arg == "--policy" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --policy requires a file path argument\n")
				return 2
			}
			i++
			policyPath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--policy=") {
			policyPath = strings.TrimPrefix(arg, "--policy=")
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

		// --allow-private
		if arg == "--allow-private" || arg == "--allow-private=true" {
			allowPrivate = true
			continue
		}
		if arg == "--allow-private=false" || arg == "--no-allow-private" {
			allowPrivate = false
			continue
		}

		// --allow-loopback
		if arg == "--allow-loopback" || arg == "--allow-loopback=true" {
			allowLoopback = true
			continue
		}
		if arg == "--allow-loopback=false" || arg == "--no-allow-loopback" {
			allowLoopback = false
			continue
		}

		// --insecure / --insecure-skip-verify
		if arg == "--insecure" || arg == "--insecure=true" || arg == "--insecure-skip-verify" || arg == "--insecure-skip-verify=true" {
			insecure = true
			continue
		}
		if arg == "--insecure=false" || arg == "--insecure-skip-verify=false" || arg == "--no-insecure" {
			insecure = false
			continue
		}

		// --active / --active-verification
		if arg == "--active" || arg == "--active=true" || arg == "--active-verification" || arg == "--active-verification=true" {
			activeVerif = true
			continue
		}
		if arg == "--active=false" || arg == "--active-verification=false" || arg == "--no-active" {
			activeVerif = false
			continue
		}

		// --notify
		if arg == "--notify" || arg == "--notify=true" {
			notifyEnabled = true
			notifyExplicit = true
			continue
		}
		if arg == "--no-notify" || arg == "--notify=false" {
			notifyEnabled = false
			notifyExplicit = true
			continue
		}

		// --webhook
		if arg == "--webhook" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --webhook requires a URL argument\n")
				return 2
			}
			i++
			webhookFlagURL = args[i]
			notifyEnabled = true
			continue
		}
		if strings.HasPrefix(arg, "--webhook=") {
			webhookFlagURL = strings.TrimPrefix(arg, "--webhook=")
			notifyEnabled = true
			continue
		}

		// --notify-provider
		if arg == "--notify-provider" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --notify-provider requires a provider type argument (webhook, slack, discord, teams)\n")
				return 2
			}
			i++
			notifyProvider = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--notify-provider=") {
			notifyProvider = strings.TrimPrefix(arg, "--notify-provider=")
			continue
		}

		// --notify-secret
		if arg == "--notify-secret" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --notify-secret requires an HMAC secret argument\n")
				return 2
			}
			i++
			notifySecret = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--notify-secret=") {
			notifySecret = strings.TrimPrefix(arg, "--notify-secret=")
			continue
		}

		// --notify-min-severity
		if arg == "--notify-min-severity" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --notify-min-severity requires a severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)\n")
				return 2
			}
			i++
			notifyMinSev = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--notify-min-severity=") {
			notifyMinSev = strings.TrimPrefix(arg, "--notify-min-severity=")
			continue
		}

		// --notify-previous-secret
		if arg == "--notify-previous-secret" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --notify-previous-secret requires a secret argument\n")
				return 2
			}
			i++
			notifyPreviousSecret = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--notify-previous-secret=") {
			notifyPreviousSecret = strings.TrimPrefix(arg, "--notify-previous-secret=")
			continue
		}

		// --notify-require-signing / --require-signing
		if arg == "--notify-require-signing" || arg == "--require-signing" {
			notifyRequireSigning = true
			continue
		}

		// --spec <path-or-url>
		if arg == "--spec" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --spec requires a file path or URL argument\n")
				return 2
			}
			i++
			specPath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--spec=") {
			specPath = strings.TrimPrefix(arg, "--spec=")
			continue
		}

		// --probe / --probe-live: Live exploitability & reachability validator (P14.3)
		if arg == "--probe" || arg == "--probe-live" {
			probeLive = true
			continue
		}

		// --profile <path>: Declarative multi-tenant scan profile (P14.4)
		if arg == "--profile" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --profile requires a file path argument\n")
				return 2
			}
			i++
			profilePath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			profilePath = strings.TrimPrefix(arg, "--profile=")
			continue
		}

		// --cross-tenant: Opt-in for cross-tenant authorization testing (P14.4)
		if arg == "--cross-tenant" || arg == "--cross-tenant=true" {
			crossTenant = true
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
	maxAssetsVal := cfgStore.MaxAssets
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

	// 7. Rate Limit Validation
	var rateLimitVal float64
	if rateLimitStr != "" {
		parsedRate, err := strconv.ParseFloat(rateLimitStr, 64)
		if err != nil || parsedRate < 0 {
			fmt.Fprintf(os.Stderr, "[-] error: invalid --rate-limit %q: must be a non-negative number\n", rateLimitStr)
			return 2
		}
		rateLimitVal = parsedRate
	}

	// 8. User Agent
	if userAgent == "" {
		userAgent = cfgStore.UserAgent
	}

	// 9. Read targets from input file if supplied
	if inputFile != "" {
		fileTargets, err := readLines(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read target file: %v\n", err)
			return 2
		}
		targets = append(targets, fileTargets...)
	}

	// 9b. Load target profile if supplied
	var targetProfile *api.TargetProfile
	if profilePath != "" {
		p, err := api.LoadTargetProfile(profilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Target profile error: %v\n", err)
			return 2
		}
		targetProfile = p
		targets = append(targets, p.Target.BaseURLs...)
	}

	if crossTenant && targetProfile == nil {
		fmt.Fprintf(os.Stderr, "[-] error: --cross-tenant requires a target profile (--profile <file>)\n")
		return 2
	}

	// 10. Ensure at least one target is specified
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Error: no target URLs specified\n\n")
		printScanHelp()
		return 2
	}

	// 11. Security Threshold Policy validation (upfront before execution)
	var pol *policy.ThresholdPolicy
	resolvedPolicyPath := strings.TrimSpace(policyPath)
	if resolvedPolicyPath == "" && cfgStore.PolicyPath != "" {
		resolvedPolicyPath = strings.TrimSpace(cfgStore.PolicyPath)
	}
	if resolvedPolicyPath != "" {
		p, err := policy.LoadPolicy(resolvedPolicyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Policy error: %v\n", err)
			return 2
		}
		pol = p
	}

	// Validate and normalize all targets according to strict authorization & syntax rules
	var normalizedTargets []string
	for _, t := range targets {
		norm, err := crawler.NormalizeTargetURL(t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] error: invalid target URL %q: %v\n", secrets.SanitizeURL(t), secrets.SanitizeError(err))
			return 2
		}
		normalizedTargets = append(normalizedTargets, norm)
	}
	targets = normalizedTargets

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
			if rateLimitVal > 0 {
				fmt.Printf("    Rate Limit:       %.1f req/s per host\n", rateLimitVal)
			}
			fmt.Printf("    Timeout:          %s\n", timeoutDuration)
			fmt.Printf("    Scope:            %s\n", scopeMode)
			if maxAssetsVal > 0 {
				fmt.Printf("    Max Assets:       %d\n", maxAssetsVal)
			} else {
				fmt.Printf("    Max Assets:       unbounded\n")
			}
			fmt.Printf("    Max Size:         %d bytes (%s)\n", maxSizeBytes, formatBytes(maxSizeBytes))
			fmt.Printf("    User-Agent:       %s\n", userAgent)
			if insecure {
				fmt.Printf("    TLS Insecure:     %t\n", insecure)
			}
			if activeVerif {
				fmt.Printf("    Active Verify:    %t\n", activeVerif)
			}
			fmt.Println()
		} else if !jsonBare {
			if rateLimitVal > 0 {
				fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Rate: %.1f req/s | Timeout: %s | Scope: %s\n\n",
					len(targets), concurrencyVal, rateLimitVal, timeoutDuration, scopeMode)
			} else {
				fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Timeout: %s | Scope: %s\n\n",
					len(targets), concurrencyVal, timeoutDuration, scopeMode)
			}
		}
	}
	_ = activeVerif

	uiProg := ui.New(ui.Options{
		Writer:   os.Stdout,
		Quiet:    quiet,
		JSONMode: jsonBare,
	})
	uiProg.Stage(1, 4, "Target Discovery & Scope Validation")

	// isClientAssetURL detects common static web assets required for frontend analysis
	// when a target is scoped to a subpath. It strictly requires both an asset directory prefix
	// (e.g. /_next/, /assets/, /static/) or standard root icon/manifest and a recognized static asset extension.
	// Normalization defeats path traversal (..), percent-encoded entities (%2e%2e), and separator bypasses.
	isClientAssetURL := func(rawURL string) bool {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return false
		}
		p := parsed.Path
		// Iteratively unescape until convergence or max 10 passes
		decoded := p
		for pass := 0; pass < 10; pass++ {
			u, err := url.PathUnescape(decoded)
			if err != nil {
				return false // Malformed escape sequence is strictly rejected
			}
			if u == decoded {
				break
			}
			decoded = u
			if pass == 9 {
				return false // Suspicious non-converging recursive encoding rejected
			}
		}
		p = decoded

		// Reject null bytes and ASCII control characters
		if strings.ContainsRune(p, 0) {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				return false
			}
		}

		// Reject residual suspicious escaped tokens (e.g. %2e, %2f, %5c, %00)
		lowerP := strings.ToLower(p)
		if strings.Contains(lowerP, "%2e") || strings.Contains(lowerP, "%2f") ||
			strings.Contains(lowerP, "%5c") || strings.Contains(lowerP, "%00") {
			return false
		}

		// Normalize backslashes to forward slashes to prevent Windows/IIS-style bypasses
		cleanP := strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))

		if cleanP == "/favicon.ico" || cleanP == "/favicon.png" || cleanP == "/manifest.json" || cleanP == "/robots.txt" {
			return true
		}
		inAssetDir := strings.HasPrefix(cleanP, "/_next/") ||
			strings.HasPrefix(cleanP, "/assets/") ||
			strings.HasPrefix(cleanP, "/static/") ||
			strings.HasPrefix(cleanP, "/build/") ||
			strings.HasPrefix(cleanP, "/dist/")
		if !inAssetDir {
			return false
		}
		ext := strings.ToLower(path.Ext(cleanP))
		switch ext {
		case ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".json", ".webmanifest":
			return true
		}
		return false
	}

	// isPathAuthorized strictly requires target origin and subpath containment.
	// Similar-prefix escapes (e.g. /hithaone-admin vs /hithaone) and cross-path routes are rejected.
	isPathAuthorized := func(u string) bool {
		for _, t := range targets {
			s, err := crawler.NewScope(t, scopeMode)
			if err == nil && s.IsPathInScope(u) {
				return true
			}
		}
		if targetProfile != nil {
			if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
				h := strings.ToLower(pu.Hostname())
				for _, ah := range targetProfile.Target.AllowedHosts {
					if h == strings.ToLower(ah) || strings.HasSuffix(h, "."+strings.ToLower(ah)) {
						return true
					}
				}
			}
		}
		return false
	}

	// isTargetAuthorized permits in-path resources and necessary static client assets (JS/CSS)
	// on the authorized host required for frontend application analysis.
	isTargetAuthorized := func(u string) bool {
		for _, t := range targets {
			s, err := crawler.NewScope(t, scopeMode)
			if err != nil {
				continue
			}
			if !s.IsAllowed(u) {
				continue
			}
			// If target has a subpath, candidate must be in path scope or be a client asset
			if s.TargetURL != nil && strings.TrimRight(s.TargetURL.Path, "/") != "" {
				if s.IsPathInScope(u) || isClientAssetURL(u) {
					return true
				}
				continue
			}
			return true
		}
		if targetProfile != nil {
			if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
				h := strings.ToLower(pu.Hostname())
				for _, ah := range targetProfile.Target.AllowedHosts {
					if h == strings.ToLower(ah) || strings.HasSuffix(h, "."+strings.ToLower(ah)) {
						return true
					}
				}
			}
		}
		return false
	}

	maxRedirects := cfgStore.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = config.DefaultMaxRedirects
	}

	// Initialize SafeTransport and wrap with RateLimitedTransport
	safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:            timeoutDuration,
		AllowLoopback:      allowLoopback,
		AllowPrivateIPs:    allowPrivate,
		InsecureSkipVerify: insecure,
	})
	rateLimitedTransport := crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{
		Rate:           rateLimitVal,
		MaxConcurrency: concurrencyVal,
	})
	safeHTTPClient := &http.Client{
		Transport: rateLimitedTransport,
		Timeout:   timeoutDuration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("invalid redirect scheme: %s", scheme)
			}
			if req.URL.User != nil {
				return fmt.Errorf("redirect URL contains embedded credentials")
			}
			destHost := req.URL.Hostname()
			if ip := net.ParseIP(destHost); ip != nil {
				if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLoopback, allowPrivate); prohibited {
					return &crawler.SSRFError{Host: destHost, IP: ip, Reason: reason}
				}
			}
			if !isPathAuthorized(req.URL.String()) {
				return fmt.Errorf("redirect to %s blocked: target is outside authorized path scope", req.URL.String())
			}
			return nil
		},
	}

	// Initialize Crawler & Security Analyzers with validated configuration and safe transport
	cConfig := crawler.Config{
		Concurrency:        concurrencyVal,
		Timeout:            timeoutDuration,
		MaxAssetSize:       maxSizeBytes,
		MaxAssets:          maxAssetsVal,
		MaxDepth:           cfgStore.MaxDepth,
		MaxRetries:         cfgStore.MaxRetries,
		RetryDelay:         time.Duration(cfgStore.RetryDelayMs) * time.Millisecond,
		MaxRedirects:       maxRedirects,
		ScopeMode:          scopeMode,
		UserAgent:          userAgent,
		Client:             safeHTTPClient,
		InsecureSkipVerify: insecure,
		AllowLoopback:      allowLoopback,
		AllowPrivateIPs:    allowPrivate,
		IsAllowed:          isTargetAuthorized,
		Progress:           uiProg.Callback(),
	}
	c := crawler.New(cConfig)
	detector := secrets.NewDetector()
	cloudAuditor := cloud.NewDetector(cloud.NewClient(cloud.ClientOptions{
		Timeout:         timeoutDuration,
		MaxResponseSize: maxSizeBytes,
		UserAgent:       userAgent,
		HTTPClient:      safeHTTPClient,
		AllowLoopback:   allowLoopback,
		AllowPrivateIPs: allowPrivate,
		IsAllowed:       isPathAuthorized,
	}), isPathAuthorized)
	cloudAuditor.SetAllowActiveVerification(activeVerif)
	apiAuditor := api.NewDetector(api.NewClient(api.ClientOptions{
		Timeout:         timeoutDuration,
		MaxResponseSize: maxSizeBytes,
		UserAgent:       userAgent,
		HTTPClient:      safeHTTPClient,
		AllowLoopback:   allowLoopback,
		AllowPrivateIPs: allowPrivate,
		IsAllowed:       isPathAuthorized,
	}), api.DetectorOptions{
		IsAllowed: isPathAuthorized,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	uiProg.Stage(2, 4, "Web & API Attack Surface Crawling")
	results := c.CrawlConcurrently(ctx, targets)

	totalDiscovered := 0
	totalEndpointsAudited := 0
	totalSecretFindings := 0
	totalCloudFindings := 0
	totalAPIFindings := 0
	var allReportFindings []report.Finding
	var allRouteCandidates []crawler.RouteCandidate
	hasNetworkSuccess := false
	blockedCount := 0
	failedCount := 0

	for res := range results {
		if res.Err != nil {
			if res.Diagnostic != nil && res.Diagnostic.IsBlocked() {
				blockedCount++
				fmt.Fprintf(os.Stderr, "[-] [%s] Target responded, but access was blocked:\n", secrets.SanitizeURL(res.Target))
				fmt.Fprintf(os.Stderr, "    Reason:     %s\n", res.Diagnostic.SafeSummary)
				if res.Diagnostic.Server != "" {
					fmt.Fprintf(os.Stderr, "    Server:     %s\n", res.Diagnostic.Server)
				}
				if res.Diagnostic.CfMitigated != "" {
					fmt.Fprintf(os.Stderr, "    Mitigation: %s\n", res.Diagnostic.CfMitigated)
				}
				if res.Diagnostic.CfRay != "" {
					fmt.Fprintf(os.Stderr, "    Ray ID:     %s\n", res.Diagnostic.CfRay)
				}
				fmt.Fprintf(os.Stderr, "    State:      BLOCKED (Access boundaries respected; probes halted)\n\n")
			} else if res.Diagnostic != nil {
				failedCount++
				fmt.Fprintf(os.Stderr, "[-] [%s] Reachability failure: %s\n\n", secrets.SanitizeURL(res.Target), res.Diagnostic.SafeSummary)
			} else {
				failedCount++
				fmt.Fprintf(os.Stderr, "[-] [%s] Error: %s\n\n", secrets.SanitizeURL(res.Target), secrets.SanitizeError(res.Err))
			}
			continue
		}
		hasNetworkSuccess = true
		uiProg.Stage(3, 4, "Vulnerability Probing & Empirical Verification")

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
			fmt.Printf("Target: %s\n\n", secrets.SanitizeURL(res.Target))
			fmt.Println("ASSET DISCOVERY & RECONNAISSANCE")
			fmt.Println("────────────────────────────────────────────────────────────")
			fmt.Printf("  • Total Assets Cataloged: %d\n", len(res.Assets))
			if jsCount > 0 {
				fmt.Printf("  • JavaScript Bundles:     %d\n", jsCount)
			}
			if cssCount > 0 {
				fmt.Printf("  • Stylesheets:            %d\n", cssCount)
			}
			if mapCount > 0 {
				fmt.Printf("  • Source Maps Identified: %d\n", mapCount)
			}
			if manifestCount > 0 {
				fmt.Printf("  • Application Manifests:  %d\n", manifestCount)
			}
			fmt.Println()
		}

		// Secret Intelligence
		secretFindings := detector.ScanAssets(res.Assets)
		if !quiet && !jsonBare {
			fmt.Println("SECRET INTELLIGENCE & CREDENTIAL AUDITING")
			fmt.Println("────────────────────────────────────────────────────────────")
			fmt.Printf("  • Source Files Analyzed:  %d\n", filesAnalyzed)
			if len(secretFindings) == 0 {
				fmt.Println("  • Exposed Credentials:    0 sensitive tokens discovered")
				fmt.Println("  • Defensive Posture:      [CLEAN] No API keys, credentials, or secrets detected in client assets.")
			} else {
				fmt.Printf("  • Findings Detected:      %d\n\n", len(secretFindings))
				fmt.Println("Findings:")
				for _, f := range secretFindings {
					fmt.Printf("  %-7s %s\n", f.Severity, secrets.RedactText(f.Title))
					fmt.Printf("          Origin:     %s:%d\n", f.FileOrigin, f.LineNumber)
					fmt.Printf("          Value:      %s\n", f.Redacted)
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
			fmt.Println("CLOUD, DATABASE & STORAGE AUDITING")
			fmt.Println("────────────────────────────────────────────────────────────")
			if len(cloudResult.DiscoveredServices) > 0 {
				fmt.Printf("  • Discovered Cloud Services (%d):\n", len(cloudResult.DiscoveredServices))
				for _, ds := range cloudResult.DiscoveredServices {
					statusStr := FormatServiceAccessState(ds, cloudResult.AccessRecords)
					target := ds.Endpoint
					if target == "" {
						target = fmt.Sprintf("%s:%d", ds.Host, ds.Port)
					}
					fmt.Printf("    [%-10s] %-14s -> %s (%s)\n", ds.Outcome, ds.Technology, target, statusStr)
				}
				fmt.Println()
			} else if sbCount == 0 && fbCount == 0 && awsCount == 0 && gcpCount == 0 {
				fmt.Println("  [✓] Surfaces Probed:   Supabase, Firebase, AWS S3, GCP, Postgres, MongoDB, Redis, Elasticsearch")
				fmt.Println("  [✓] Public Exposure:   0 unauthenticated cloud databases or storage buckets exposed")
				fmt.Println("  [✓] Defensive Posture: [DEFENDED] Target data tier is not publicly reachable from external boundary.")
				fmt.Println("                         Services are either private VPC-isolated, screened behind edge WAF/firewall,")
				fmt.Println("                         or Row-Level Security (RLS) is strictly enforced.")
				fmt.Println()
			} else {
				fmt.Println("  Discovered Cloud Providers:")
				if sbCount > 0 {
					fmt.Printf("    • Supabase: %d service(s)\n", sbCount)
				}
				if fbCount > 0 {
					fmt.Printf("    • Firebase: %d service(s)\n", fbCount)
				}
				if awsCount > 0 {
					fmt.Printf("    • AWS:      %d resource(s)\n", awsCount)
				}
				if gcpCount > 0 {
					fmt.Printf("    • GCP:      %d resource(s)\n", gcpCount)
				}
				fmt.Println()
			}

			if len(cloudResult.ConnectionIndicators) > 0 {
				fmt.Printf("  • Connection Indicators (%d):\n", len(cloudResult.ConnectionIndicators))
				for _, ci := range cloudResult.ConnectionIndicators {
					credStatus := "endpoint only"
					if ci.HasCredentials {
						credStatus = "credentials detected"
					}
					fmt.Printf("    [%-21s] %-14s -> %s (%s, %s)\n", ci.Type, ci.Technology, ci.Endpoint, ci.Source.Identifier, credStatus)
				}
				fmt.Println()
			}

			if len(cloudResult.Findings) > 0 {
				fmt.Println("Findings:")
				for _, f := range cloudResult.Findings {
					fmt.Printf("  %-6s %s\n", f.Severity, secrets.RedactText(f.Description))
					fmt.Printf("         Endpoint:   %s\n", secrets.SanitizeURL(f.Endpoint))
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
			fmt.Println("API SECURITY AUDITING & ENDPOINT POSTURE")
			fmt.Println("────────────────────────────────────────────────────────────")
			fmt.Printf("  • Endpoints Audited:      %d\n", apiResult.EndpointsScanned)
			if len(apiResult.DiscoveredEndpoints) > 0 {
				fmt.Printf("  • Discovered Endpoints:   %d\n", len(apiResult.DiscoveredEndpoints))
			}
			fmt.Printf("  • GraphQL Endpoints:      %d\n", apiResult.GraphQLCount)
			fmt.Printf("  • Sensitive Endpoints:    %d\n", apiResult.SensitiveCount)
			fmt.Printf("  • CORS Policy Checks:     %d\n", apiResult.CORSCount)
			fmt.Printf("  • Security Header Checks: %d\n", apiResult.HeaderCount)
			if len(apiResult.Findings) == 0 {
				fmt.Println("  • Verification Posture:   [DEFENDED] No unauthenticated API vulnerabilities identified.")
			}
			fmt.Println()

			if len(apiResult.Findings) > 0 {
				fmt.Println("Findings:")
				for _, f := range apiResult.Findings {
					fmt.Printf("  %-7s [%s] %s\n", f.Severity, f.Category, secrets.RedactText(f.Description))
					fmt.Printf("          Endpoint:   %s (%s)\n", secrets.SanitizeURL(f.Endpoint), f.Method)
					if f.Evidence != "" {
						fmt.Printf("          Evidence:   %s\n", api.RedactEvidence(f.Evidence))
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
		allRouteCandidates = append(allRouteCandidates, res.RouteCandidates...)

		if verbose && len(res.Assets) > 0 {
			fmt.Println("Discovered Assets Inventory:")
			fmt.Println("────────────────────────────────────────")
			for _, a := range res.Assets {
				label := assetLabel(a.Type)
				statusSuffix := ""
				if a.Error != nil {
					statusSuffix = fmt.Sprintf(" [%s]", secrets.SanitizeError(a.Error))
				} else if !a.InScope {
					statusSuffix = " [external / skipped]"
				}
				fmt.Printf("%-8s %s%s\n", label, secrets.SanitizeURL(a.URL), statusSuffix)
			}
			fmt.Println()
		}

		totalDiscovered += len(res.Assets)
	}

	assessmentState := "COMPLETED"
	if !hasNetworkSuccess && len(targets) > 0 {
		if blockedCount > 0 && failedCount == 0 {
			assessmentState = "BLOCKED"
			fmt.Fprintf(os.Stderr, "[-] Assessment status: BLOCKED (Target access denied or challenge presented; security posture unevaluated).\n")
		} else {
			assessmentState = "FAILED"
			fmt.Fprintf(os.Stderr, "[-] Assessment status: FAILED (Target(s) could not be reached).\n")
		}

		duration := time.Since(startTime)
		rep := report.BuildMultiTargetReport(targets, nil)
		rep.Duration = duration.Round(time.Millisecond).String()
		rep.DurationMs = duration.Milliseconds()
		rep.CompletionStatus = assessmentState
		rep.RiskScore = 0
		rep.RiskLevel = "UNAVAILABLE"
		rep.RiskScoreAvailable = false
		rep.Summary.ScoreAvailable = false
		reqCount := int(rateLimitedTransport.TotalRequests())
		rep.RequestCount = reqCount
		if rep.Metadata == nil {
			rep.Metadata = make(map[string]any)
		}
		rep.Metadata["crawled_assets_count"] = 0
		rep.Metadata["transport_requests_count"] = reqCount
		rep.Metadata["wire_requests_count"] = reqCount
		rep.Metadata["peak_concurrency"] = rateLimitedTransport.PeakConcurrency()
		report.RecalculateReportRisk(&rep)

		if outStr != "" {
			if err := report.WriteJSON(rep, outStr); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to save scan result to %s: %v\n", outStr, err)
			}
		}
		if jsonPath != "" {
			if err := report.WriteJSON(rep, jsonPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to export JSON report to %s: %v\n", jsonPath, err)
			}
		}
		if htmlStr != "" {
			if err := report.WriteHTML(rep, htmlStr); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to export HTML report to %s: %v\n", htmlStr, err)
			}
		}
		if sarifPath != "" {
			if err := report.WriteSARIF(rep, sarifPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to export SARIF report to %s: %v\n", sarifPath, err)
			}
		}
		if exportStr != "" {
			files := strings.Split(exportStr, ",")
			for _, f := range files {
				f = strings.TrimSpace(f)
				if f == "" {
					continue
				}
				lowerF := strings.ToLower(f)
				if strings.HasSuffix(lowerF, ".html") {
					if err := report.WriteHTML(rep, f); err != nil {
						fmt.Fprintf(os.Stderr, "[-] Failed to export HTML to %s: %v\n", f, err)
					}
				} else if strings.HasSuffix(lowerF, ".sarif") {
					if err := report.WriteSARIF(rep, f); err != nil {
						fmt.Fprintf(os.Stderr, "[-] Failed to export SARIF to %s: %v\n", f, err)
					}
				} else {
					if err := report.WriteJSON(rep, f); err != nil {
						fmt.Fprintf(os.Stderr, "[-] Failed to export JSON to %s: %v\n", f, err)
					}
				}
			}
		}

		dispatchReportNotification(rep, cfgStore, scanNotifyOptions{
			enabled:        notifyEnabled,
			explicit:       notifyExplicit,
			webhookURL:     webhookFlagURL,
			provider:       notifyProvider,
			secret:         notifySecret,
			previousSecret: notifyPreviousSecret,
			requireSigning: notifyRequireSigning,
			minSeverity:    notifyMinSev,
			allowPrivate:   allowPrivate,
			allowLoopback:  allowLoopback,
			insecure:       insecure,
			quiet:          quiet,
		})
		return 2
	} else if blockedCount > 0 || failedCount > 0 {
		assessmentState = "PARTIAL"
	}

	duration := time.Since(startTime)
	uiProg.Stage(4, 4, "Security Posture Synthesis & Reporting")

	// Build unified assessment report from the single scan execution
	rep := report.BuildMultiTargetReport(targets, allReportFindings)
	rep.Duration = duration.Round(time.Millisecond).String()
	rep.DurationMs = duration.Milliseconds()

	transportRequests := int(rateLimitedTransport.TotalRequests())
	if transportRequests > 0 {
		rep.RequestCount = transportRequests
	} else {
		rep.RequestCount = totalDiscovered + totalEndpointsAudited
	}
	rep.CompletionStatus = assessmentState
	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["crawled_assets_count"] = totalDiscovered
	rep.Metadata["transport_requests_count"] = transportRequests
	rep.Metadata["wire_requests_count"] = transportRequests // preserved alias for backwards compatibility
	rep.Metadata["peak_concurrency"] = rateLimitedTransport.PeakConcurrency()
	if duration.Seconds() > 0 && transportRequests > 0 {
		rep.Metadata["effective_req_per_sec"] = float64(transportRequests) / duration.Seconds()
	}

	// P14.2: Shadow vs. Documented API Topology Reconciliation
	var reconciliationReport *api.ReconciliationReport
	if specPath != "" {
		parser := api.NewSpecParser()
		var specOps []api.DocumentedOperation
		var specMeta *api.SpecMetadata
		var parseErr error

		if strings.HasPrefix(specPath, "http://") || strings.HasPrefix(specPath, "https://") {
			req, rErr := http.NewRequestWithContext(ctx, http.MethodGet, specPath, nil)
			if rErr == nil {
				req.Header.Set("User-Agent", userAgent)
				req.Header.Set("Accept", "application/json,application/yaml,text/yaml,*/*")
				resp, dErr := safeHTTPClient.Do(req)
				if dErr == nil && resp.StatusCode == 200 {
					defer resp.Body.Close()
					data, _ := io.ReadAll(io.LimitReader(resp.Body, api.MaxSpecificationFileSize))
					specOps, specMeta, parseErr = parser.ParseSpecificationData(data, specPath)
				} else {
					parseErr = fmt.Errorf("failed fetching specification from %s", specPath)
				}
			}
		} else {
			specOps, specMeta, parseErr = parser.ParseSpecificationFile(specPath)
		}

		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: Specification parsing issue for %s: %v\n", specPath, parseErr)
			if specMeta == nil {
				specMeta = &api.SpecMetadata{
					Source:   specPath,
					Format:   "MALFORMED",
					Warnings: []string{parseErr.Error()},
				}
			}
		}

		var specsList []api.SpecMetadata
		if specMeta != nil {
			specsList = append(specsList, *specMeta)
		}

		engine := api.NewReconciliationEngine(specsList, specOps, api.DefaultReconciliationOptions())
		reconciliationReport = engine.Reconcile(allRouteCandidates)

		rep.Reconciliation = reconciliationReport
		rep.Metadata["reconciliation"] = reconciliationReport
		rep.Metadata["shadow_surface_count"] = len(reconciliationReport.ShadowSurface)
		rep.Metadata["undocumented_routes_count"] = reconciliationReport.TotalUndocumentedCandidates
		rep.Metadata["sensitive_shadow_routes_count"] = reconciliationReport.TotalSensitiveShadowRoutes

		if !quiet && reconciliationReport != nil {
			fmt.Println()
			fmt.Println("================================================================================")
			fmt.Println("Shadow API Surface & Topology Reconciliation (P14.2)")
			fmt.Println("================================================================================")
			specDesc := "None"
			if specMeta != nil {
				specDesc = fmt.Sprintf("%s (%s: %s)", specMeta.Title, specMeta.Format, specMeta.Source)
			}
			fmt.Printf("  Specification:          %s\n", specDesc)
			fmt.Printf("  Documented Operations:  %d\n", reconciliationReport.TotalDocumentedOperations)
			fmt.Printf("  Discovered Routes:      %d\n", reconciliationReport.TotalDiscoveredCandidates)
			fmt.Printf("  Documented Matches:     %d\n", reconciliationReport.TotalDocumentedMatches)
			fmt.Printf("  Undocumented (Shadow):  %d\n", reconciliationReport.TotalUndocumentedCandidates)
			fmt.Printf("  Sensitive Boundaries:   %d\n", reconciliationReport.TotalSensitiveShadowRoutes)
			fmt.Printf("  Ambiguous Matches:      %d\n", reconciliationReport.TotalAmbiguousMatches)
			if len(reconciliationReport.ShadowSurface) > 0 {
				fmt.Println("\n  High-Priority Shadow API Candidates:")
				for idx, ss := range reconciliationReport.ShadowSurface {
					if idx >= 10 && !verbose {
						fmt.Printf("  ... and %d more shadow candidates (use --verbose to view all)\n", len(reconciliationReport.ShadowSurface)-10)
						break
					}
					sensTag := ""
					if len(ss.SensitiveHits) > 0 {
						var types []string
						for _, sh := range ss.SensitiveHits {
							types = append(types, string(sh.Type))
						}
						sensTag = fmt.Sprintf(" [%s]", strings.Join(types, ", "))
					}
					fmt.Printf("  [%s] %-6s %s%s\n", ss.Priority, ss.Method, ss.CanonicalPath, sensTag)
					if verbose {
						fmt.Printf("    Rationale: %s\n", ss.MatchRationale)
						fmt.Printf("    Source:    %s (%s)\n", ss.DiscoverySource, ss.OriginatingAsset)
					}
				}
			}
			fmt.Println("================================================================================")
			fmt.Println()
		}
	}

	// P14.3: Zero-False-Positive Live Exploitability Prober
	if probeLive {
		var probeCandidates []api.ReconciliationItem
		if reconciliationReport != nil && len(reconciliationReport.ShadowSurface) > 0 {
			probeCandidates = reconciliationReport.ShadowSurface
		} else if len(allRouteCandidates) > 0 {
			for _, rc := range allRouteCandidates {
				probeCandidates = append(probeCandidates, api.ReconciliationItem{
					CandidateID:   rc.ID,
					Path:          rc.Path,
					Method:        rc.HTTPMethod,
					CanonicalPath: api.CanonicalizeRoutePath(rc.Path),
				})
			}
		}

		if len(probeCandidates) > 0 {
			targetBaseURL := ""
			scopeHost := ""
			if len(targets) > 0 {
				targetBaseURL = targets[0]
				if u, err := url.Parse(targetBaseURL); err == nil {
					scopeHost = strings.ToLower(u.Hostname())
				}
			}

			proberOpts := api.DefaultProberOptions()
			proberOpts.AllowLoopback = allowLoopback
			proberOpts.AllowPrivateIPs = allowPrivate
			proberOpts.ScopeHost = scopeHost
			if userAgent != "" {
				proberOpts.UserAgent = userAgent
			}
			if rateLimitVal > 0 {
				proberOpts.RateLimit = rateLimitVal
			}
			proberOpts.IsAllowed = isPathAuthorized

			proberEngine := api.NewProberEngine(proberOpts)
			proberReport := proberEngine.ProbeBatch(ctx, probeCandidates, targetBaseURL)

			rep.ProberResults = proberReport
			if rep.Metadata == nil {
				rep.Metadata = make(map[string]any)
			}
			rep.Metadata["prober_results"] = proberReport
			rep.Metadata["reachable_routes_count"] = proberReport.TotalReachable
			rep.Metadata["metadata_routes_count"] = proberReport.TotalReachableWithMetadata
			rep.Metadata["auth_required_routes_count"] = proberReport.TotalAuthenticationRequired

			if !quiet && proberReport != nil {
				fmt.Println()
				fmt.Println("================================================================================")
				fmt.Println("Live Shadow API Exploitability & Reachability Prober (P14.3)")
				fmt.Println("================================================================================")
				fmt.Printf("  Candidates Evaluated:      %d\n", proberReport.TotalCandidatesEvaluated)
				fmt.Printf("  Probes Attempted:          %d\n", proberReport.TotalProbesAttempted)
				fmt.Printf("  Empirically Reachable:     %d\n", proberReport.TotalReachable)
				fmt.Printf("  Structured API Metadata:   %d\n", proberReport.TotalReachableWithMetadata)
				fmt.Printf("  Authentication Enforced:   %d\n", proberReport.TotalAuthenticationRequired)
				fmt.Printf("  Authorization Denied:      %d\n", proberReport.TotalAuthorizationDenied)
				fmt.Printf("  Not Found Responses:       %d\n", proberReport.TotalNotFound)
				fmt.Printf("  Upstream Failures:         %d\n", proberReport.TotalUpstreamFailures)
				fmt.Printf("  Scope / SSRF Blocked:      %d\n", proberReport.TotalScopeBlocked)
				fmt.Printf("  Inconclusive Findings:     %d\n", proberReport.TotalInconclusive)
				fmt.Printf("  Manual Verification Need:  %d\n", proberReport.ManualVerificationCandidates)

				if len(proberReport.Results) > 0 {
					fmt.Println("\n  Live Probe Evidence Summary:")
					for idx, pr := range proberReport.Results {
						if idx >= 10 && !verbose {
							fmt.Printf("  ... and %d more probe outcomes (use --verbose to view all)\n", len(proberReport.Results)-10)
							break
						}
						statusStr := "-"
						if pr.StatusCode > 0 {
							statusStr = fmt.Sprintf("%d", pr.StatusCode)
						}
						fmt.Printf("  [%-18s] %-7s %-4s %s\n", pr.Classification, pr.ProbeMethod, statusStr, pr.CanonicalPath)
						if verbose {
							fmt.Printf("    Rationale: %s\n", pr.Rationale)
							if pr.HasStructuredMetadata {
								fmt.Printf("    Metadata:  %s\n", pr.StructuredMetadataType)
							}
							if pr.RedirectInfo != nil {
								fmt.Printf("    Redirect:  %s (In-Scope: %t)\n", pr.RedirectInfo.RedirectURL, pr.RedirectInfo.IsInScope)
							}
						}
					}
				}
				fmt.Println("================================================================================")
				fmt.Println()
			}
		}
	}

	// P14.4: Declarative Multi-Tenant & Cross-Tenant Authorization Checks
	if targetProfile != nil && (crossTenant || targetProfile.CrossTenantTests.Enabled) {
		mtOpts := api.MultiTenantEngineOptions{
			CLIOptIn:        crossTenant,
			AllowLoopback:   allowLoopback,
			AllowPrivateIPs: allowPrivate,
			ScopeValidator:  isPathAuthorized,
			UserAgent:       userAgent,
		}
		mtEngine := api.NewMultiTenantEngine(targetProfile, mtOpts)
		xtcReport := mtEngine.RunCrossTenantChecks(ctx)

		rep.CrossTenantResults = xtcReport
		if rep.Metadata == nil {
			rep.Metadata = make(map[string]any)
		}
		rep.Metadata["cross_tenant_results"] = xtcReport
		rep.Metadata["cross_tenant_bola_observed_count"] = xtcReport.TotalCrossTenantAccessObserved
		rep.Metadata["cross_tenant_executed_count"] = xtcReport.TotalExecuted

		// Synthesize verified BOLA findings into report findings for risk score calculation
		for _, res := range xtcReport.Results {
			if res.IsBOLAObserved {
				finding := report.Finding{
					ID:       fmt.Sprintf("FND-BOLA-%s", res.ComparisonID),
					RuleID:   "API-BOLA-001",
					Status:   report.FindingStatusConfirmed,
					Severity: "CRITICAL",
					Category: "Broken Object Level Authorization (BOLA)",
					Title:    fmt.Sprintf("Cross-Tenant Object Access: Tenant %s accessed %s resource %s", res.RequesterTenant, res.ResourceOwnerTenant, res.ResourceID),
					Description: res.Rationale,
					Endpoint: res.TargetURL,
					Method:   res.Method,
					Source:   report.SourceAPI,
					EvidenceDetails: report.EvidenceDetails{
						Observation:     res.Rationale,
						Location:        res.TargetURL,
						HTTPMethod:      res.Method,
						HTTPStatus:      res.StatusCode,
						DetectionMethod: "cross_tenant_probe",
						DetectionStatus: "CONFIRMED",
						ObservedBehavior: fmt.Sprintf("Tenant %s successfully retrieved resource owned by %s", res.RequesterTenant, res.ResourceOwnerTenant),
						Details: map[string]string{
							"requester_tenant":      res.RequesterTenant,
							"resource_owner_tenant": res.ResourceOwnerTenant,
							"resource_id":          res.ResourceID,
							"comparison_id":         res.ComparisonID,
							"evidence_snippet":      res.EvidenceSnippet,
						},
					},
					Verification: report.VerificationRecord{
						Status: report.VerificationVerified,
						Result: res.Rationale,
					},
					Remediation: "Implement strict authorization checks verifying that the authenticated tenant owns the requested resource before returning object data.",
					Score: 90,
				}
				rep.Findings = append(rep.Findings, finding)
			}
		}

		if !quiet && xtcReport != nil {
			fmt.Println()
			fmt.Println("================================================================================")
			fmt.Println("Multi-Tenant Isolation & Cross-Tenant Authorization Checks (P14.4)")
			fmt.Println("================================================================================")
			fmt.Printf("  Comparisons Configured:     %d\n", xtcReport.TotalComparisonsConfigured)
			fmt.Printf("  Executed Probes:            %d\n", xtcReport.TotalExecuted)
			fmt.Printf("  Cross-Tenant Access (BOLA): %d\n", xtcReport.TotalCrossTenantAccessObserved)
			fmt.Printf("  Access Denied (403):        %d\n", xtcReport.TotalAccessDeniedObserved)
			fmt.Printf("  Not Found (404):            %d\n", xtcReport.TotalNotFoundObserved)
			fmt.Printf("  Inconclusive Probes:        %d\n", xtcReport.TotalInconclusive)
			fmt.Printf("  Skipped Probes:             %d\n", xtcReport.TotalSkipped)
			if len(xtcReport.Warnings) > 0 {
				for _, w := range xtcReport.Warnings {
					fmt.Printf("  [Notice] %s\n", w)
				}
			}
			if len(xtcReport.Results) > 0 {
				fmt.Println("\n  Cross-Tenant Probe Outcomes:")
				for _, res := range xtcReport.Results {
					tag := string(res.Classification)
					if res.IsBOLAObserved {
						tag = "BOLA OBSERVED"
					}
					statusStr := "-"
					if res.StatusCode > 0 {
						statusStr = fmt.Sprintf("%d", res.StatusCode)
					}
					fmt.Printf("  [%-14s] %s -> %s | Res: %s | HTTP %s\n", tag, res.RequesterTenant, res.ResourceOwnerTenant, res.ResourceID, statusStr)
					if verbose {
						fmt.Printf("    Rationale: %s\n", res.Rationale)
						if res.EvidenceSnippet != "" {
							fmt.Printf("    Snippet:   %s\n", res.EvidenceSnippet)
						}
					}
				}
			}
			fmt.Println("================================================================================")
			fmt.Println()
		}
	}

	report.RecalculateReportRisk(&rep)

	var exported []string
	var exportErrs []error

	// 1. Export JSON scan result if requested
	if outStr != "" {
		if err := report.WriteJSON(rep, outStr); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save scan result to %s: %v\n", outStr, err)
			exportErrs = append(exportErrs, err)
		} else {
			exported = append(exported, fmt.Sprintf("  Scan Result (JSON): %s", outStr))
		}
	}
	if jsonPath != "" {
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export JSON report to %s: %v\n", jsonPath, err)
			exportErrs = append(exportErrs, err)
		} else {
			exported = append(exported, fmt.Sprintf("  JSON Report:        %s", jsonPath))
		}
	}

	// 2. Export HTML if requested via --html
	if htmlStr != "" {
		if err := report.WriteHTML(rep, htmlStr); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export HTML report to %s: %v\n", htmlStr, err)
			exportErrs = append(exportErrs, err)
		} else {
			exported = append(exported, fmt.Sprintf("  HTML Report:        %s", htmlStr))
		}
	}

	// 3. Export SARIF if requested via --sarif
	if sarifPath != "" {
		if err := report.WriteSARIF(rep, sarifPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to export SARIF report to %s: %v\n", sarifPath, err)
			exportErrs = append(exportErrs, err)
		} else {
			exported = append(exported, fmt.Sprintf("  SARIF Report:       %s", sarifPath))
		}
	}

	// 4. Export via canonical --export flag (single or comma-separated HTML/JSON/SARIF)
	if exportStr != "" {
		files := strings.Split(exportStr, ",")
		for _, f := range files {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			lowerF := strings.ToLower(f)
			if strings.HasSuffix(lowerF, ".html") {
				if err := report.WriteHTML(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export HTML to %s: %v\n", f, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  HTML Report:        %s", f))
				}
			} else if strings.HasSuffix(lowerF, ".sarif") {
				if err := report.WriteSARIF(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export SARIF to %s: %v\n", f, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  SARIF Report:       %s", f))
				}
			} else {
				if err := report.WriteJSON(rep, f); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to export JSON to %s: %v\n", f, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  JSON Report:        %s", f))
				}
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

		if rep.CommercialReport != nil && rep.CommercialReport.AttackSurface.TotalAssets > 0 {
			fmt.Printf("[*] Assessment complete in %s. %d frontend asset(s) crawled, %d attack-surface resource(s) cataloged, %d finding(s) discovered across %d target(s).\n",
				rep.Duration, totalDiscovered, rep.CommercialReport.AttackSurface.TotalAssets, len(rep.Findings), len(targets))
		} else {
			fmt.Printf("[*] Assessment complete in %s. %d frontend asset(s) crawled, %d finding(s) discovered across %d target(s).\n",
				rep.Duration, totalDiscovered, len(rep.Findings), len(targets))
		}
	}

	var policyDecision *policy.EvaluationDecision
	var policyErr error
	if pol != nil {
		ctx := policy.EvaluationContext{
			Status:      rep.CompletionStatus,
			TargetScope: targets,
		}
		decision, err := policy.EvaluateReport(pol, &rep, ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Policy evaluation error: %v\n", err)
			policyErr = err
		} else {
			policyDecision = decision
			if rep.Metadata == nil {
				rep.Metadata = make(map[string]any)
			}
			rep.Metadata["policy_evaluation"] = decision
			if !quiet && !jsonBare {
				fmt.Print(policy.FormatDecisionSummary(decision))
			}
		}
	}

	dispatchReportNotification(rep, cfgStore, scanNotifyOptions{
		enabled:        notifyEnabled,
		explicit:       notifyExplicit,
		webhookURL:     webhookFlagURL,
		provider:       notifyProvider,
		secret:         notifySecret,
		previousSecret: notifyPreviousSecret,
		requireSigning: notifyRequireSigning,
		minSeverity:    notifyMinSev,
		allowPrivate:   allowPrivate,
		allowLoopback:  allowLoopback,
		insecure:       insecure,
		quiet:          quiet,
	})

	if pol != nil {
		hasViolation := policyDecision != nil && !policyDecision.Passed
		cls := clierror.ClassifyAssessment(rep.CompletionStatus, nil, hasViolation, policyErr, exportErrs...)
		return cls.ExitCode()
	}

	// No policy configured
	if len(exportErrs) > 0 {
		return clierror.ExitOperational
	}
	return determineExitCode(rep)
}

func printScanHelp() {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  felix scan [options] <target-url | path-to-apk>")
	fmt.Println("\nExecute an automated security assessment against target web assets or Android APK packages.")
	fmt.Println("\nOptions:")
	fmt.Println("  --timeout <duration>        Network timeout per target (e.g. 10s, 30s, 1m) [default: 10s]")
	fmt.Println("  --concurrency <int>         Number of concurrent workers [default: 10]")
	fmt.Println("  --rate-limit, -r <float>    Maximum requests per second per host (0 = unlimited)")
	fmt.Println("  --scope <mode>              Crawl scope mode (same-origin, subdomains, explicit) [default: same-origin]")
	fmt.Println("  --max-assets <int>          Maximum number of assets to process/discover")
	fmt.Println("  --max-response-size <size>  Maximum asset response size (e.g. 10MB, 512KB) [default: 10MB]")
	fmt.Println("  --export <file>             Export assessment report to HTML, JSON, or SARIF file")
	fmt.Println("  --json [file]               Save machine-readable scan result as JSON (or output to stdout)")
	fmt.Println("  --sarif [file]              Export assessment report to SARIF 2.1.0 format")
	fmt.Println("  --policy <file>             Evaluate security threshold policy against completed assessment")
	fmt.Println("  --spec <file>               Client-provided OpenAPI / Swagger specification for shadow API reconciliation")
	fmt.Println("  --probe, --probe-live       Safely probe discovered shadow API candidates for live reachability and metadata")
	fmt.Println("  --profile <file>            Declarative multi-tenant scan profile (felix.target.yml)")
	fmt.Println("  --cross-tenant              Opt-in to controlled cross-tenant authorization (BOLA) verification")
	fmt.Println("  --quiet, -q                 Suppress normal terminal output and banners")
	fmt.Println("  --verbose, -v               Enable detailed operational output")
	fmt.Println("  -l <file>                   Path to file containing target URLs (one per line)")
	fmt.Println("  --user-agent <string>       Custom User-Agent header string")
	fmt.Println("  --allow-private             Allow connections to RFC 1918 private subnets")
	fmt.Println("  --allow-loopback            Allow connections to loopback addresses (127.0.0.0/8, ::1)")
	fmt.Println("  --insecure                  Skip TLS certificate verification (default: false)")
	fmt.Println("  --active                    Enable active vulnerability verification (default: false)")
	fmt.Println("  --notify                    Send completion notification upon assessment termination")
	fmt.Println("  --webhook <url>             Destination HTTPS webhook URL for notification dispatch")
	fmt.Println("  --notify-provider <type>    Notification transport provider (webhook, slack, discord, teams)")
	fmt.Println("  --notify-secret <secret>    HMAC-SHA256 signature secret (supports env:VAR_NAME to avoid process exposure)")
	fmt.Println("  --notify-previous-secret <secret> Previous HMAC secret for key rotation (supports env:VAR_NAME)")
	fmt.Println("  --notify-require-signing    Fail closed if webhook notifications cannot be cryptographically signed")
	fmt.Println("  --notify-min-severity <sev> Minimum finding severity threshold to trigger alert")
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

// FormatServiceAccessState returns an evidence-supported display string for discovered service access status.
func FormatServiceAccessState(ds cloud.DiscoveredService, accessRecords ...[]cloud.AccessVerificationRecord) string {
	if !ds.InScope {
		return "Outside authorized scope"
	}
	target := ds.Endpoint
	if target == "" && ds.Host != "" {
		if ds.Port > 0 {
			target = net.JoinHostPort(ds.Host, strconv.Itoa(ds.Port))
		} else {
			target = ds.Host
		}
	}

	if len(accessRecords) > 0 {
		for _, rec := range accessRecords[0] {
			if rec.Technology == ds.Technology && (rec.Target == target || rec.Target == ds.Endpoint || rec.Target == ds.Host) {
				switch rec.Status {
				case cloud.StatusReadAllowed:
					if rec.ResourceScope != "" {
						return fmt.Sprintf("Read verified (%s)", rec.ResourceScope)
					}
					return "Read access verified"
				case cloud.StatusUnauthenticatedAccess:
					return "Unauthenticated access verified"
				case cloud.StatusAuthenticatedAccess:
					return "Authenticated access verified"
				case cloud.StatusWriteVerified:
					return "Write access verified"
				case cloud.StatusAuthChallenged:
					return "Authentication challenge observed"
				case cloud.StatusReadDenied, cloud.StatusWriteDenied:
					return "Access restricted (denied)"
				case cloud.StatusServiceReachable:
					return "Service reachable (data access not verified)"
				case cloud.StatusVerificationSkipped:
					return "Verification skipped (active verify disabled)"
				case cloud.StatusAccessInconclusive:
					return "Access inconclusive"
				}
			}
		}
	}

	if ds.PublicAccess {
		return "Access verified"
	}
	if ds.AuthRequired {
		return "Authentication observed"
	}
	return "Access not verified"
}
