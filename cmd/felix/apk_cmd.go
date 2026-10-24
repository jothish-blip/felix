package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"path/filepath"
	"strings"
	"time"

	"felix/pkg/apk"
	"felix/pkg/assessment"
	"felix/pkg/config"
	"felix/pkg/report"
)

// runAPK executes the "felix apk" subcommand for APK intake, structural validation, and isolation.
func runAPK(args []string) int {
	cfgStore, _ := config.LoadWithEnv("")
	var (
		extract          bool
		keepWorkspace    bool
		jsonOutput       bool
		quiet            bool
		analyzeManifest  bool
		analyzeArtifacts bool
		buildInventory   bool
		assessBackend    bool
		dryRun           bool
		scopeTargets     []string
		scopeMode        string
		exclusions       []string
		authorizingParty string
		authConfirm      bool
		allowInferred    bool
		allowThirdParty  bool
		allowLoopback    bool
		maxRequests      int
		maxPerHost       int
		rateLimit        float64
		concurrency      int
		perReqTimeout    time.Duration
		overallDeadline  time.Duration
		generateReport   bool
		reportPath       string
		jsonFilePath     string
		sarifOutput      bool
		sarifPath        string
		exportPath       string
		apkPath          string
		limits           = apk.DefaultLimits()
		notifyEnabled    = cfgStore.Notification.Enabled
		notifyExplicit   bool
		webhookFlagURL   string
		notifyProvider       string
		notifySecret         string
		notifyPreviousSecret string
		notifyRequireSigning bool
		notifyMinSev         string
	)

	// Custom argument parser matching Felix CLI conventions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			printAPKHelp()
			return 0
		}
		if arg == "--report" || arg == "--html" {
			generateReport = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasSuffix(strings.ToLower(args[i+1]), ".apk") {
				i++
				reportPath = args[i]
			}
			continue
		}
		if strings.HasPrefix(arg, "--report=") {
			generateReport = true
			reportPath = strings.TrimPrefix(arg, "--report=")
			continue
		}
		if strings.HasPrefix(arg, "--html=") {
			generateReport = true
			reportPath = strings.TrimPrefix(arg, "--html=")
			continue
		}
		if arg == "--output" || arg == "-o" || arg == "--out" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a file path argument\n", arg)
				return 2
			}
			i++
			reportPath = args[i]
			generateReport = true
			continue
		}
		if strings.HasPrefix(arg, "--output=") {
			reportPath = strings.TrimPrefix(arg, "--output=")
			generateReport = true
			continue
		}
		if strings.HasPrefix(arg, "--out=") {
			reportPath = strings.TrimPrefix(arg, "--out=")
			generateReport = true
			continue
		}
		if arg == "--extract" {
			extract = true
			continue
		}
		if arg == "--keep-workspace" || arg == "--keep" {
			keepWorkspace = true
			continue
		}
		if arg == "--json" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasSuffix(strings.ToLower(args[i+1]), ".apk") {
				i++
				jsonFilePath = args[i]
			} else {
				jsonOutput = true
			}
			continue
		}
		if strings.HasPrefix(arg, "--json=") {
			jsonFilePath = strings.TrimPrefix(arg, "--json=")
			continue
		}
		if arg == "--sarif" {
			sarifOutput = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasSuffix(strings.ToLower(args[i+1]), ".apk") {
				i++
				sarifPath = args[i]
			}
			continue
		}
		if strings.HasPrefix(arg, "--sarif=") {
			sarifOutput = true
			sarifPath = strings.TrimPrefix(arg, "--sarif=")
			continue
		}
		if arg == "--export" || arg == "-e" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a file path argument\n", arg)
				return 2
			}
			i++
			exportPath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--export=") {
			exportPath = strings.TrimPrefix(arg, "--export=")
			continue
		}
		if strings.HasPrefix(arg, "-e=") {
			exportPath = strings.TrimPrefix(arg, "-e=")
			continue
		}
		if arg == "--quiet" || arg == "-q" || arg == "--silent" || arg == "-s" {
			quiet = true
			continue
		}
		if arg == "--verbose" || arg == "-v" {
			continue
		}
		if arg == "--analyze" {
			analyzeManifest = true
			analyzeArtifacts = true
			buildInventory = true
			continue
		}
		if arg == "--inventory" {
			buildInventory = true
			continue
		}
		if arg == "--analyze-manifest" {
			analyzeManifest = true
			continue
		}
		if arg == "--analyze-artifacts" {
			analyzeArtifacts = true
			continue
		}
		if arg == "--assess" || arg == "--handoff" {
			assessBackend = true
			analyzeManifest = true
			analyzeArtifacts = true
			buildInventory = true
			continue
		}
		if arg == "--target" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --target requires a URL argument\n")
				return 2
			}
			i++
			scopeTargets = append(scopeTargets, args[i])
			continue
		}
		if strings.HasPrefix(arg, "--target=") {
			scopeTargets = append(scopeTargets, strings.TrimPrefix(arg, "--target="))
			continue
		}
		if arg == "--scope-mode" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --scope-mode requires a mode argument (same-origin, subdomains, explicit)\n")
				return 2
			}
			i++
			scopeMode = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--scope-mode=") {
			scopeMode = strings.TrimPrefix(arg, "--scope-mode=")
			continue
		}
		if arg == "--exclude" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --exclude requires a pattern argument\n")
				return 2
			}
			i++
			exclusions = append(exclusions, args[i])
			continue
		}
		if strings.HasPrefix(arg, "--exclude=") {
			exclusions = append(exclusions, strings.TrimPrefix(arg, "--exclude="))
			continue
		}
		if arg == "--authorizing-party" || arg == "--auth-party" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a party name argument\n", arg)
				return 2
			}
			i++
			authorizingParty = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--authorizing-party=") {
			authorizingParty = strings.TrimPrefix(arg, "--authorizing-party=")
			continue
		}
		if arg == "--auth-confirm" {
			authConfirm = true
			continue
		}
		if arg == "--allow-inferred" {
			allowInferred = true
			continue
		}
		if arg == "--allow-third-party" {
			allowThirdParty = true
			continue
		}
		if arg == "--allow-loopback" {
			allowLoopback = true
			continue
		}
		if arg == "--dry-run" {
			dryRun = true
			continue
		}
		if arg == "--max-requests" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --max-requests requires an integer argument\n")
				return 2
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --max-requests %q: must be a positive integer\n", args[i])
				return 2
			}
			maxRequests = n
			continue
		}
		if arg == "--max-per-host" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --max-per-host requires an integer argument\n")
				return 2
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --max-per-host %q: must be a positive integer\n", args[i])
				return 2
			}
			maxPerHost = n
			continue
		}
		if arg == "--rate-limit" || arg == "-r" || arg == "--rate" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a number argument\n", arg)
				return 2
			}
			i++
			f, err := strconv.ParseFloat(args[i], 64)
			if err != nil || f <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --rate-limit %q: must be positive\n", args[i])
				return 2
			}
			rateLimit = f
			continue
		}
		if strings.HasPrefix(arg, "--rate-limit=") || strings.HasPrefix(arg, "-r=") || strings.HasPrefix(arg, "--rate=") {
			v := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(arg, "--rate-limit="), "-r="), "--rate=")
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --rate-limit %q: must be positive\n", v)
				return 2
			}
			rateLimit = f
			continue
		}
		if arg == "--concurrency" || arg == "-c" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires an integer argument\n", arg)
				return 2
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --concurrency %q: must be a positive integer\n", args[i])
				return 2
			}
			concurrency = n
			continue
		}
		if strings.HasPrefix(arg, "--concurrency=") || strings.HasPrefix(arg, "-c=") {
			v := strings.TrimPrefix(strings.TrimPrefix(arg, "--concurrency="), "-c=")
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --concurrency %q: must be a positive integer\n", v)
				return 2
			}
			concurrency = n
			continue
		}
		if arg == "--timeout" || arg == "-t" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a duration argument (e.g. 5s, 10s)\n", arg)
				return 2
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --timeout %q: must be a positive duration\n", args[i])
				return 2
			}
			perReqTimeout = d
			continue
		}
		if strings.HasPrefix(arg, "--timeout=") || strings.HasPrefix(arg, "-t=") {
			v := strings.TrimPrefix(strings.TrimPrefix(arg, "--timeout="), "-t=")
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --timeout %q: must be a positive duration\n", v)
				return 2
			}
			perReqTimeout = d
			continue
		}
		if arg == "--overall-timeout" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --overall-timeout requires a duration argument (e.g. 30s, 1m)\n")
				return 2
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --overall-timeout %q: must be a positive duration\n", args[i])
				return 2
			}
			overallDeadline = d
			continue
		}

		// --max-compressed-size
		if arg == "--max-compressed-size" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --max-compressed-size requires a byte count argument\n")
				return 2
			}
			i++
			n, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --max-compressed-size %q: must be a positive integer\n", args[i])
				return 2
			}
			limits.MaxCompressedSize = n
			continue
		}

		// --max-entries
		if arg == "--max-entries" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --max-entries requires an integer argument\n")
				return 2
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "[-] error: invalid --max-entries %q: must be a positive integer\n", args[i])
				return 2
			}
			limits.MaxArchiveEntries = n
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

		// Positional argument: apkPath
		if !strings.HasPrefix(arg, "-") {
			if apkPath == "" {
				apkPath = arg
			} else {
				fmt.Fprintf(os.Stderr, "[-] error: unexpected extra argument: %s\n", arg)
				return 2
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "[-] error: unrecognized flag: %s\n", arg)
		printAPKHelp()
		return 2
	}

	if apkPath == "" {
		fmt.Fprintf(os.Stderr, "[-] error: APK input file path is required\n\n")
		printAPKHelp()
		return 2
	}

	if generateReport && reportPath == "" {
		reportPath = apk.DefaultMobileAuditReportName
	}
	if (generateReport || sarifOutput || jsonFilePath != "" || exportPath != "") && !analyzeManifest && !analyzeArtifacts && !buildInventory && !assessBackend {
		analyzeManifest = true
		analyzeArtifacts = true
		buildInventory = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	opts := apk.IntakeOptions{
		Limits:  limits,
		Extract: extract || analyzeManifest || analyzeArtifacts || buildInventory, // extract safe entries to enable manifest, artifact, and inventory inspection
	}

	res, err := apk.Intake(ctx, apkPath, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] APK intake rejected: %v\n", err)
		return 2
	}

	// Always ensure cleanup unless user explicitly requested --keep-workspace
	if !keepWorkspace {
		defer res.Workspace.Close()
	}

	// Optional manifest static security analysis
	var manifestRes *apk.ManifestAnalysisResult
	if analyzeManifest || buildInventory {
		manifestRes, err = apk.AnalyzeManifest(ctx, res.Workspace, limits)
		if err != nil && analyzeManifest {
			fmt.Fprintf(os.Stderr, "[-] Manifest analysis failed: %v\n", err)
			return 2
		}
	}

	// Optional application artifact static intelligence analysis
	var artifactRes *apk.ArtifactAnalysisResult
	if analyzeArtifacts || buildInventory {
		artifactRes, err = apk.AnalyzeArtifacts(ctx, res.Workspace, limits)
		if err != nil && analyzeArtifacts {
			fmt.Fprintf(os.Stderr, "[-] Artifact analysis failed: %v\n", err)
			return 2
		}
	}

	// Optional backend inventory synthesis
	var inventoryRes *apk.BackendInventory
	if buildInventory {
		inventoryRes, err = apk.BuildBackendInventory(ctx, res.Workspace, manifestRes, artifactRes, limits)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Backend inventory failed: %v\n", err)
			return 2
		}
	}

	// Pre-flight validation for active backend assessment
	if assessBackend {
		if len(scopeTargets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: Active backend assessment requires explicit authorized scope targets.\n")
			fmt.Fprintf(os.Stderr, "    Specify approved target URL(s) with --target <url>.\n")
			fmt.Fprintf(os.Stderr, "    (Endpoints discovered during APK intake never confer automatic testing authorization.)\n")
			return 2
		}
		if authorizingParty == "" && !authConfirm {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: Missing authorization certification.\n")
			fmt.Fprintf(os.Stderr, "    Specify --authorizing-party <name> or --auth-confirm to certify explicit authorization to test the backend.\n")
			return 2
		}
	}

	// Optional authorized backend assessment handoff
	var handoffReport *apk.HandoffReport
	if assessBackend && inventoryRes != nil {
		validFrom := time.Now().Add(-1 * time.Hour)
		validUntil := time.Now().Add(24 * time.Hour)
		partyName := authorizingParty
		if partyName == "" {
			partyName = "CLI Operator (Explicit --auth-confirm)"
		}
		authRecord := &assessment.AuthorizationRecord{
			ID:                  "auth-cli-" + strconv.FormatInt(time.Now().Unix(), 10),
			AuthorizingParty:    partyName,
			AuthorizationMethod: "WRITTEN_CONTRACT",
			Status:              assessment.AuthApproved,
			ValidFrom:           &validFrom,
			ValidUntil:          &validUntil,
		}

		handoffCfg := apk.DefaultHandoffConfig()
		handoffCfg.AuthorizedTargets = scopeTargets
		if scopeMode != "" {
			handoffCfg.ScopeMode = scopeMode
		}
		handoffCfg.Authorization = authRecord
		handoffCfg.AllowInferredRoutes = allowInferred
		handoffCfg.AllowThirdParties = allowThirdParty
		handoffCfg.AllowLoopback = allowLoopback
		handoffCfg.DryRun = dryRun
		if maxRequests > 0 {
			handoffCfg.MaxRequestsTotal = maxRequests
		}
		if maxPerHost > 0 {
			handoffCfg.MaxRequestsPerHost = maxPerHost
		}
		if rateLimit > 0 {
			handoffCfg.RateLimit = rateLimit
		}
		if concurrency > 0 {
			handoffCfg.MaxConcurrency = concurrency
		}
		if perReqTimeout > 0 {
			handoffCfg.PerRequestTimeout = perReqTimeout
		}
		if overallDeadline > 0 {
			handoffCfg.OverallDeadline = overallDeadline
		}
		for _, exc := range exclusions {
			handoffCfg.Exclusions = append(handoffCfg.Exclusions, assessment.Exclusion{
				ExclusionType: assessment.ExclusionHostname,
				Pattern:       exc,
				Reason:        "CLI exclusion rule",
			})
		}

		hRep, err := apk.ExecuteHandoff(ctx, inventoryRes, handoffCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Backend assessment failed: %v\n", err)
			return 2
		}
		handoffReport = hRep
	}

	if jsonOutput {
		outObj := map[string]interface{}{
			"status":                   "PASS",
			"sha256":                   res.SHA256,
			"file_size":                res.FileSize,
			"entry_count":              res.EntryCount,
			"total_decompressed_bytes": res.TotalDecompressedBytes,
			"manifest_present":         res.ManifestPresent,
			"dex_count":                res.DexCount,
			"dex_files":                res.DexFiles,
			"intake_status":            "VALIDATED_AND_ISOLATED",
			"security_assessment":      "PENDING_STATIC_ANALYSIS",
		}
		if keepWorkspace {
			outObj["workspace_dir"] = res.Workspace.Path()
		}
		if manifestRes != nil || artifactRes != nil || inventoryRes != nil {
			outObj["security_assessment"] = "EVALUATED"
		}
		if manifestRes != nil && analyzeManifest {
			outObj["manifest_analysis"] = map[string]interface{}{
				"format":         manifestRes.Document.Format,
				"package_name":   manifestRes.Document.PackageName,
				"min_sdk":        manifestRes.Document.MinSDK,
				"target_sdk":     manifestRes.Document.TargetSDK,
				"findings_count": len(manifestRes.Findings),
				"findings":       manifestRes.Findings,
				"limitations":    manifestRes.Limitations,
			}
		}
		if artifactRes != nil && analyzeArtifacts {
			outObj["artifact_analysis"] = map[string]interface{}{
				"dex_files_analyzed":    artifactRes.DexFilesAnalyzed,
				"configs_analyzed":      artifactRes.ConfigsAnalyzed,
				"findings_count":        artifactRes.FindingsCount,
				"findings":              artifactRes.Findings,
				"limitations":           artifactRes.Limitations,
				"unsupported_artifacts": artifactRes.UnsupportedArtifacts,
				"partial_analysis":      artifactRes.PartialAnalysis,
				"summary":               artifactRes.Summary,
			}
		}
		if inventoryRes != nil {
			outObj["backend_inventory"] = inventoryRes
		}
		if handoffReport != nil {
			outObj["backend_handoff"] = handoffReport
		}
		if err := writeAPKReports(apkPath, reportPath, generateReport, jsonFilePath, sarifOutput, sarifPath, exportPath, res, manifestRes, artifactRes, inventoryRes, handoffReport, outObj, quiet); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			return 2
		}
		mobileRep := apk.BuildMobileReportData(apkPath, res, manifestRes, artifactRes, inventoryRes, handoffReport).ToReport()
		dispatchReportNotification(mobileRep, cfgStore, scanNotifyOptions{
			enabled:        notifyEnabled,
			explicit:       notifyExplicit,
			webhookURL:     webhookFlagURL,
			provider:       notifyProvider,
			secret:         notifySecret,
			previousSecret: notifyPreviousSecret,
			requireSigning: notifyRequireSigning,
			minSeverity:    notifyMinSev,
			allowPrivate:   allowLoopback || cfgStore.AllowPrivateIPs,
			allowLoopback:  allowLoopback || cfgStore.AllowLoopback,
			insecure:       cfgStore.InsecureSkipVerify,
			quiet:          quiet,
		})
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(outObj)
		return 0
	}

	if !quiet {
		fmt.Print(banner)
		fmt.Println("===========================================================")
		fmt.Println("  FELIX :: APK INTAKE AND ISOLATION")
		fmt.Println("===========================================================")
		fmt.Printf("  Target APK:              %s\n", apkPath)
		fmt.Printf("  SHA-256 Digest:          %s\n", res.SHA256)
		fmt.Printf("  File Size:               %d bytes (%.2f MB)\n", res.FileSize, float64(res.FileSize)/(1024*1024))
		fmt.Printf("  Archive Entries:         %d entries\n", res.EntryCount)
		fmt.Printf("  Decompressed Size:       %d bytes (%.2f MB)\n", res.TotalDecompressedBytes, float64(res.TotalDecompressedBytes)/(1024*1024))
		fmt.Printf("  AndroidManifest.xml:     CONFIRMED (staged in isolated workspace)\n")
		fmt.Printf("  Dalvik Executables:      %d (.dex file(s) discovered)\n", res.DexCount)
		if keepWorkspace {
			fmt.Printf("  Isolated Workspace:      %s (retained)\n", res.Workspace.Path())
		} else {
			fmt.Printf("  Isolated Workspace:      Ephemeral (cleaned up automatically)\n")
		}
		fmt.Println("-----------------------------------------------------------")

		if manifestRes != nil {
			fmt.Println("===========================================================")
			fmt.Println("  FELIX :: ANDROID MANIFEST SECURITY ANALYSIS")
			fmt.Println("===========================================================")
			fmt.Printf("  Package Name:            %s\n", manifestRes.Document.PackageName)
			fmt.Printf("  Manifest Format:         %s\n", manifestRes.Document.Format)
			fmt.Printf("  Min SDK / Target SDK:    %d / %d\n", manifestRes.Document.MinSDK, manifestRes.Document.TargetSDK)
			fmt.Printf("  Findings Identified:     %d\n", len(manifestRes.Findings))
			fmt.Println("-----------------------------------------------------------")

			if len(manifestRes.Findings) == 0 {
				fmt.Println("  No security exposures or non-standard configurations identified.")
			} else {
				for _, f := range manifestRes.Findings {
					fmt.Printf("  [%s] %s\n", f.Severity, f.Title)
					fmt.Printf("    Target/Component: %s\n", f.Endpoint)
					fmt.Printf("    Observation:      %s\n", f.Evidence)
					fmt.Printf("    Remediation:      %s\n", f.Remediation)
					fmt.Println()
				}
			}
			fmt.Println("===========================================================")
			fmt.Println("  Status:                  PASS (Manifest static assessment complete; offline)")
			fmt.Println("===========================================================")
		}

		if artifactRes != nil {
			fmt.Println("===========================================================")
			fmt.Println("  FELIX :: APPLICATION ARTIFACT INTELLIGENCE")
			fmt.Println("===========================================================")
			fmt.Printf("  DEX Files Analyzed:      %d (%s)\n", len(artifactRes.DexFilesAnalyzed), strings.Join(artifactRes.DexFilesAnalyzed, ", "))
			fmt.Printf("  Configurations Analyzed: %d\n", len(artifactRes.ConfigsAnalyzed))
			fmt.Printf("  Discovered Secrets:      %d\n", artifactRes.Summary.SecretsCount)
			fmt.Printf("  Service Indicators:      %d\n", artifactRes.Summary.ServicesCount)
			fmt.Printf("  API Endpoints / Routes:  %d\n", artifactRes.Summary.EndpointsCount)
			fmt.Printf("  GraphQL References:      %d\n", artifactRes.Summary.GraphQLCount)
			fmt.Printf("  Total Findings:          %d\n", artifactRes.FindingsCount)
			fmt.Println("-----------------------------------------------------------")

			if len(artifactRes.Findings) == 0 {
				fmt.Println("  No exposed secrets, services, or endpoints discovered in artifacts.")
			} else {
				for _, f := range artifactRes.Findings {
					fmt.Printf("  [%s] %s\n", f.Severity, f.Title)
					fmt.Printf("    Location:    %s\n", f.Endpoint)
					fmt.Printf("    Observation: %s\n", f.Evidence)
					fmt.Printf("    Remediation: %s\n", f.Remediation)
					fmt.Println()
				}
			}

			if len(artifactRes.Limitations) > 0 {
				fmt.Println("  Limitations:")
				for _, l := range artifactRes.Limitations {
					fmt.Printf("    * %s\n", l)
				}
				fmt.Println()
			}
			fmt.Println("===========================================================")
			fmt.Println("  Status:                  PASS (Artifact intelligence complete; offline)")
			fmt.Println("===========================================================")
		}

		if inventoryRes != nil {
			fmt.Println("===========================================================")
			fmt.Println("  FELIX :: BACKEND INVENTORY")
			fmt.Println("===========================================================")
			fmt.Printf("  Total Endpoints:         %d\n", inventoryRes.TotalEndpoints)
			fmt.Printf("  Backend Hosts:           %d\n", inventoryRes.TotalHosts)
			fmt.Printf("  Confirmed References:    %d\n", inventoryRes.ConfirmedCount)
			fmt.Printf("  Inferred Routes:         %d\n", inventoryRes.InferredCount)
			if len(inventoryRes.Categories) > 0 {
				var catList []string
				for c, cnt := range inventoryRes.Categories {
					catList = append(catList, fmt.Sprintf("%s: %d", c, cnt))
				}
				sort.Strings(catList)
				fmt.Printf("  Categories:              %s\n", strings.Join(catList, ", "))
			}
			fmt.Println("-----------------------------------------------------------")

			if len(inventoryRes.Hosts) == 0 {
				fmt.Println("  No backend hosts or endpoints discovered in APK artifacts.")
			} else {
				for _, h := range inventoryRes.Hosts {
					fmt.Printf("  Host: %s (%d endpoint(s))\n", h.HostIdentity, h.EndpointCount)
					if len(h.ServiceIndicators) > 0 {
						fmt.Printf("    Services:    %s\n", strings.Join(h.ServiceIndicators, ", "))
					}
					for _, ep := range h.Endpoints {
						provStr := ""
						if len(ep.Provenance) > 0 {
							provStr = fmt.Sprintf(" [%s]", ep.Provenance[0].ArtifactPath)
						}
						fmt.Printf("    * [%s] %s%s\n", ep.Classification, ep.NormalizedURL, provStr)
					}
					fmt.Println()
				}
			}

			if len(inventoryRes.Limitations) > 0 {
				fmt.Println("  Limitations:")
				for _, l := range inventoryRes.Limitations {
					fmt.Printf("    * %s\n", l)
				}
				fmt.Println()
			}
			fmt.Println("===========================================================")
			fmt.Println("  Status:                  PASS (Backend inventory complete; offline)")
			fmt.Println("===========================================================")
		}

		if handoffReport != nil {
			fmt.Println("===========================================================")
			fmt.Println("  FELIX :: AUTHORIZED BACKEND HANDOFF & ASSESSMENT")
			fmt.Println("===========================================================")
			fmt.Printf("  Scope Mode:              %s\n", handoffReport.ScopeMode)
			fmt.Printf("  Authorized Targets:      %s\n", strings.Join(handoffReport.AuthorizedTargets, ", "))
			fmt.Printf("  Dry Run (Planning):      %t\n", handoffReport.DryRun)
			fmt.Printf("  Execution Duration:      %dms\n", handoffReport.DurationMs)
			fmt.Println("-----------------------------------------------------------")
			fmt.Printf("  Total Discovered:        %d\n", handoffReport.TotalDiscovered)
			fmt.Printf("  Eligible Candidates:     %d\n", handoffReport.TotalEligible)
			fmt.Printf("  Authorized in Scope:     %d\n", handoffReport.TotalAuthorized)
			fmt.Printf("  Tested (Dispatched):     %d\n", handoffReport.TotalTested)
			fmt.Printf("  Skipped:                 %d\n", handoffReport.TotalSkipped)
			fmt.Printf("  Failed:                  %d\n", handoffReport.TotalFailed)
			fmt.Printf("  Inconclusive:            %d\n", handoffReport.TotalInconclusive)
			fmt.Printf("  Requests Dispatched:     %d\n", handoffReport.TotalRequestsSent)
			fmt.Printf("  Budget Exhausted:        %t\n", handoffReport.BudgetExhausted)
			fmt.Println("-----------------------------------------------------------")
			fmt.Println("  Endpoint Dispositions:")
			for _, r := range handoffReport.Results {
				dispInfo := r.ReasonCode
				if r.Disposition == apk.DispositionTested {
					dispInfo = fmt.Sprintf("HTTP %d, %dms", r.HTTPStatus, r.DurationMs)
				}
				fmt.Printf("    * [%s] %s (%s)\n", strings.ToUpper(string(r.Disposition)), r.NormalizedURL, dispInfo)
			}
			if len(handoffReport.Limitations) > 0 {
				fmt.Println()
				fmt.Println("  Limitations & Safeguards:")
				for _, l := range handoffReport.Limitations {
					fmt.Printf("    * %s\n", l)
				}
			}
			fmt.Println("===========================================================")
			statusMsg := "PASS (Authorized backend assessment complete)"
			if handoffReport.DryRun {
				statusMsg = "PASS (Dry-run planning complete; zero network requests dispatched)"
			}
			fmt.Printf("  Status:                  %s\n", statusMsg)
			fmt.Println("===========================================================")
		}

		if !assessBackend && (manifestRes != nil || artifactRes != nil || inventoryRes != nil) {
			fmt.Println("  Active Assessment:       Disabled (offline static analysis only; pass --assess --target <url> --auth-confirm)")
		}

		if manifestRes == nil && artifactRes == nil && inventoryRes == nil {
			fmt.Println("  Status:                  PASS (Intake boundary verified; offline static-only)")
			fmt.Println("  Security Posture:        Unevaluated (Pass --analyze to run static security analysis)")
			fmt.Println("===========================================================")
		}
	}

	if err := writeAPKReports(apkPath, reportPath, generateReport, jsonFilePath, sarifOutput, sarifPath, exportPath, res, manifestRes, artifactRes, inventoryRes, handoffReport, nil, quiet); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return 2
	}

	mobileRep := apk.BuildMobileReportData(apkPath, res, manifestRes, artifactRes, inventoryRes, handoffReport).ToReport()
	dispatchReportNotification(mobileRep, cfgStore, scanNotifyOptions{
		enabled:        notifyEnabled,
		explicit:       notifyExplicit,
		webhookURL:     webhookFlagURL,
		provider:       notifyProvider,
		secret:         notifySecret,
		previousSecret: notifyPreviousSecret,
		requireSigning: notifyRequireSigning,
		minSeverity:    notifyMinSev,
		allowPrivate:   allowLoopback || cfgStore.AllowPrivateIPs,
		allowLoopback:  allowLoopback || cfgStore.AllowLoopback,
		insecure:       cfgStore.InsecureSkipVerify,
		quiet:          quiet,
	})

	return 0
}

func writeAPKReports(
	apkPath string,
	reportPath string,
	generateReport bool,
	jsonFilePath string,
	sarifOutput bool,
	sarifPath string,
	exportPath string,
	res *apk.IntakeResult,
	manifestRes *apk.ManifestAnalysisResult,
	artifactRes *apk.ArtifactAnalysisResult,
	inventoryRes *apk.BackendInventory,
	handoffReport *apk.HandoffReport,
	outObj map[string]interface{},
	quiet bool,
) error {
	if !generateReport && jsonFilePath == "" && !sarifOutput && exportPath == "" {
		return nil
	}

	reportData := apk.BuildMobileReportData(apkPath, res, manifestRes, artifactRes, inventoryRes, handoffReport)
	canonicalReport := reportData.ToReport()

	if generateReport {
		if err := apk.WriteMobileAuditReport(reportData, reportPath, apkPath); err != nil {
			return fmt.Errorf("failed generating mobile audit report: %w", err)
		}
		if outObj != nil {
			outObj["report_file"] = reportPath
		}
		if !quiet && outObj == nil {
			fmt.Println("===========================================================")
			fmt.Printf("  Mobile Audit Report:     %s\n", reportPath)
			fmt.Println("===========================================================")
		}
	}

	if jsonFilePath != "" {
		if err := report.WriteJSON(canonicalReport, jsonFilePath); err != nil {
			return fmt.Errorf("failed writing JSON report: %w", err)
		}
		if outObj != nil {
			outObj["json_report_file"] = jsonFilePath
		}
		if !quiet && outObj == nil {
			fmt.Println("===========================================================")
			fmt.Printf("  JSON Report:             %s\n", jsonFilePath)
			fmt.Println("===========================================================")
		}
	}

	if sarifOutput {
		targetSarif := sarifPath
		if targetSarif == "" {
			targetSarif = "report.sarif"
		}
		if err := report.WriteSARIF(canonicalReport, targetSarif); err != nil {
			return fmt.Errorf("failed writing SARIF report: %w", err)
		}
		if outObj != nil {
			outObj["sarif_report_file"] = targetSarif
		}
		if !quiet && outObj == nil {
			fmt.Println("===========================================================")
			fmt.Printf("  SARIF Report (2.1.0):    %s\n", targetSarif)
			fmt.Println("===========================================================")
		}
	}

	if exportPath != "" {
		ext := strings.ToLower(filepath.Ext(exportPath))
		var exportErr error
		switch ext {
		case ".sarif":
			exportErr = report.WriteSARIF(canonicalReport, exportPath)
		case ".html", ".htm":
			if strings.Contains(strings.ToLower(exportPath), "commercial") && canonicalReport.CommercialReport != nil {
				exportErr = report.WriteCommercialHTML(*canonicalReport.CommercialReport, exportPath)
			} else {
				exportErr = apk.WriteMobileAuditReport(reportData, exportPath, apkPath)
			}
		default:
			exportErr = report.WriteJSON(canonicalReport, exportPath)
		}
		if exportErr != nil {
			return fmt.Errorf("failed exporting report: %w", exportErr)
		}
		if outObj != nil {
			outObj["export_file"] = exportPath
		}
		if !quiet && outObj == nil {
			fmt.Println("===========================================================")
			fmt.Printf("  Exported Report:         %s\n", exportPath)
			fmt.Println("===========================================================")
		}
	}

	return nil
}

func printAPKHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix apk [options] <path-to-apk>")
	fmt.Println("\nSafely validate and isolate Android APK packages for offline static analysis.")
	fmt.Println("\nOptions:")
	fmt.Println("  --analyze                     Run complete static security analysis (manifest and artifacts)")
	fmt.Println("  --analyze-manifest            Run static security analysis on AndroidManifest.xml")
	fmt.Println("  --analyze-artifacts           Run static intelligence analysis on DEX and embedded artifacts")
	fmt.Println("  --inventory                   Build backend endpoint and host inventory from APK artifacts")
	fmt.Println("  --assess, --handoff           Execute authorized active backend assessment on discovered inventory")
	fmt.Println("  --target <url>                Authorized target URL (mandatory with --assess)")
	fmt.Println("  --scope-mode <mode>           Scope mode: same-origin (default), subdomains, or explicit")
	fmt.Println("  --exclude <pattern>           URL or hostname pattern to explicitly exclude from active testing")
	fmt.Println("  --authorizing-party <name>    Entity or contract certifying authorization to test the backend")
	fmt.Println("  --auth-confirm                Certify explicit authorization to conduct active backend assessment")
	fmt.Println("  --allow-inferred              Permit testing of resolved inferred routes (default: false)")
	fmt.Println("  --allow-third-party           Permit testing of third-party domains (default: false)")
	fmt.Println("  --allow-loopback              Permit testing against loopback/localhost (testing only; default: false)")
	fmt.Println("  --dry-run                     Plan candidates and dispositions without sending active network traffic")
	fmt.Println("  --report [file]               Generate standalone mobile audit HTML report (default: mobile_audit.html)")
	fmt.Println("  --html [file]                 Alias for --report")
	fmt.Println("  --output <file>, -o <file>    Specify output report path (default: mobile_audit.html)")
	fmt.Println("  --max-requests <n>            Maximum total network requests allowed for the assessment (default: 50)")
	fmt.Println("  --max-per-host <n>            Maximum network requests allowed per backend host (default: 20)")
	fmt.Println("  --rate-limit <rps>            Maximum request rate in requests per second (default: 10)")
	fmt.Println("  --concurrency <n>             Maximum concurrent active probes (default: 2)")
	fmt.Println("  --timeout <duration>          Per-request timeout (default: 5s)")
	fmt.Println("  --overall-timeout <duration>  Overall assessment deadline (default: 30s)")
	fmt.Println("  --extract                     Extract all safe entries to the isolated workspace")
	fmt.Println("  --keep-workspace, --keep      Retain the isolated temporary workspace directory on disk")
	fmt.Println("  --json                        Output machine-readable validation results as JSON")
	fmt.Println("  --quiet, -q                   Suppress banner and verbose operational output")
	fmt.Println("  --max-compressed-size <n>     Maximum allowed input APK file size in bytes (default: 200MB)")
	fmt.Println("  --max-entries <n>             Maximum allowed archive entries (default: 20000)")
	fmt.Println("  --notify                      Send completion notification upon assessment termination")
	fmt.Println("  --webhook <url>             Destination HTTPS webhook URL for notification dispatch")
	fmt.Println("  --notify-provider <type>    Notification transport provider (webhook, slack, discord, teams)")
	fmt.Println("  --notify-secret <secret>      HMAC-SHA256 signature secret (supports env:VAR_NAME to avoid process exposure)")
	fmt.Println("  --notify-previous-secret <secret> Previous HMAC secret for key rotation (supports env:VAR_NAME)")
	fmt.Println("  --notify-require-signing      Fail closed if webhook notifications cannot be cryptographically signed")
	fmt.Println("  --notify-min-severity <sev> Minimum finding severity threshold to trigger alert")
	fmt.Println("  --help, -h                    Show this help message")
}
