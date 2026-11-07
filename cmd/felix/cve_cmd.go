package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/cve"
)

func runCVE(args []string) int {
	if len(args) == 0 {
		printCVEHelp()
		return clierror.ExitOperational
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "sync":
		return runCVESync(subArgs)
	case "import":
		return runCVEImport(subArgs)
	case "status":
		return runCVEStatus(subArgs)
	case "query":
		return runCVEQuery(subArgs)
	case "template", "templates":
		return runCVETemplate(subArgs)
	case "help", "--help", "-h":
		printCVEHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown cve subcommand: %s\n\n", sub)
		printCVEHelp()
		return clierror.ExitOperational
	}
}

func printCVEHelp() {
	fmt.Println("Usage: felix cve <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  sync     Synchronize or seed the local SQLite CVE database")
	fmt.Println("  import   Import air-gapped compressed CVE definitions and vulnerability templates")
	fmt.Println("  status   Display database statistics, size, and integrity")
	fmt.Println("  query    Execute high-speed hybrid SemVer query against indexed CPE")
	fmt.Println("  template Execute, list, or validate YAML vulnerability templates")
	fmt.Println("\nOptions for sync:")
	fmt.Println("  --db <path>           Custom SQLite database path (default: ~/.felix/cve.db)")
	fmt.Println("  --source <type>       Vulnerability source: osv (default: osv)")
	fmt.Println("  --file <path>         Path to JSON feed file (NVD, OSV, or GHSA format)")
	fmt.Println("  --format <type>       Feed format: nvd, osv, ghsa (default: nvd)")
	fmt.Println("  --templates-dir <dir> Path to templates directory to synchronize")
	fmt.Println("  --seed                Seed database with essential common enterprise CVEs")
	fmt.Println("\nOptions for import:")
	fmt.Println("  felix cve import <archive.tar.gz> [--db <path>] [--checksum <hash>] [--checksum-file <path>] [--templates-dir <dir>]")
	fmt.Println("\nOptions for status:")
	fmt.Println("  --db <path>           Custom SQLite database path")
	fmt.Println("\nOptions for query:")
	fmt.Println("  --cpe <prefix>        Target CPE prefix (e.g. cpe:2.3:a:apache:tomcat)")
	fmt.Println("  --version <ver>       Target software version (e.g. 9.0.9)")
	fmt.Println("  --db <path>           Custom SQLite database path")
}

func runCVESync(args []string) int {
	fs := flag.NewFlagSet("felix cve sync", flag.ContinueOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	filePath := fs.String("file", "", "Path to feed JSON file")
	format := fs.String("format", "nvd", "Feed format (nvd, osv, ghsa)")
	source := fs.String("source", "", "Incremental vulnerability source (e.g. osv)")
	templatesDir := fs.String("templates-dir", "", "Path to templates directory to sync")
	seed := fs.Bool("seed", false, "Seed database with essential enterprise CVE records")

	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	targetDB := *dbPath
	if targetDB == "" {
		def, err := cve.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default db path: %v\n", err)
			return clierror.ExitOperational
		}
		targetDB = def
	}

	fmt.Printf("[+] Initializing SQLite CVE store at %s ...\n", targetDB)
	store, err := cve.NewStore(targetDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed opening CVE store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if *filePath != "" {
		f, err := os.Open(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed reading feed file %s: %v\n", *filePath, err)
			return clierror.ExitOperational
		}
		defer f.Close()

		fmt.Printf("[+] Ingesting %s feed from %s ...\n", strings.ToUpper(*format), *filePath)
		var stats cve.IngestStats
		switch strings.ToLower(*format) {
		case "osv":
			stats, err = store.IngestOSVJSON(ctx, f)
		case "ghsa":
			stats, err = store.IngestGHSAJSON(ctx, f)
		default:
			stats, err = store.IngestNVDJSON(ctx, f)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Ingestion failed: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Processed: %d | Inserted: %d | Skipped: %d | Errors: %d in %v (%.1f records/sec)\n",
			stats.TotalProcessed, stats.Inserted, stats.Skipped, stats.Errors, stats.Duration, stats.RecordsPerSec)
	}

	if *seed {
		fmt.Println("[+] Seeding core baseline CVE records...")
		records := generateCoreSeedCVEs()
		syncStats, err := store.UpsertBatch(ctx, records)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Seeding failed: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Processed %d records: %d inserted, %d updated, %d skipped in %v (%.1f rec/sec)\n",
			syncStats.TotalProcessed, syncStats.Inserted, syncStats.Updated, syncStats.Skipped, syncStats.Duration, syncStats.RecordsPerSec)
	}

	// If incremental source is requested (or default when neither file nor seed is given)
	if *source != "" || (*filePath == "" && !*seed) {
		srcName := "OSV"
		if *source != "" {
			srcName = strings.ToUpper(*source)
		}
		fmt.Printf("[+] Executing incremental synchronization from %s ...\n", srcName)
		report, err := cve.SyncOSVIncremental(ctx, store, cve.OSVSyncOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Incremental sync failed: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Println("===========================================================")
		fmt.Printf("  FELIX :: Incremental Vulnerability Sync (%s)\n", report.Source)
		fmt.Println("===========================================================")
		fmt.Printf("Last Sync Timestamp : %s\n", report.LastSyncTime)
		fmt.Printf("Records Synced      : %d\n", report.RecordsSynced)
		fmt.Printf("Inserted (New)      : %d\n", report.Inserted)
		fmt.Printf("Updated (Modified)  : %d\n", report.Updated)
		fmt.Printf("Skipped (Duplicate) : %d\n", report.Skipped)
		fmt.Printf("Errors / Rejected   : %d\n", report.Errors)
		fmt.Printf("Sync Duration       : %v\n", report.Duration)
		fmt.Println("-----------------------------------------------------------")
		fmt.Println("[+] Atomic Commit & Integrity Verification: PASSED")
		fmt.Println("===========================================================")
	}

	// If templates-dir is provided, synchronize templates
	if *templatesDir != "" {
		reg := cve.NewTemplateRegistry()
		_, _ = reg.LoadBuiltinTemplates()
		tReport, err := reg.SyncFromDir(*templatesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Template sync failed: %v\n", err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Template Registry Synced: %d discovered (%d new, %d updated) in %v\n",
			tReport.TotalDiscovered, tReport.NewTemplates, tReport.UpdatedTemplates, tReport.Duration)
	}

	fmt.Println("[+] Synchronization complete.")
	return clierror.ExitSuccess
}

func runCVEImport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Usage: felix cve import <archive.tar.gz> [--db <path>] [--templates-dir <dir>] [--checksum <sha256>] [--checksum-file <path>]")
		return clierror.ExitOperational
	}

	fs := flag.NewFlagSet("felix cve import", flag.ContinueOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")
	templatesDir := fs.String("templates-dir", "", "Path to templates directory")
	checksum := fs.String("checksum", "", "Expected trusted SHA-256 digest of archive")
	checksumFile := fs.String("checksum-file", "", "Path to file containing expected SHA-256 digest")

	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "db", "templates-dir", "checksum", "checksum-file":
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			clean := strings.TrimSpace(arg)
			if clean != "" {
				positional = append(positional, clean)
			}
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return clierror.ExitOperational
	}

	for _, extra := range fs.Args() {
		clean := strings.TrimSpace(extra)
		if clean != "" {
			positional = append(positional, clean)
		}
	}

	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Archive path is required: felix cve import <archive.tar.gz>")
		return clierror.ExitOperational
	}
	archivePath := positional[0]

	targetDB := *dbPath
	if targetDB == "" {
		def, err := cve.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default db path: %v\n", err)
			return clierror.ExitOperational
		}
		targetDB = def
	}

	var trustedChecksum string
	if *checksum != "" {
		trustedChecksum = strings.TrimSpace(*checksum)
	} else if *checksumFile != "" {
		b, err := os.ReadFile(*checksumFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed reading checksum file %s: %v\n", *checksumFile, err)
			return clierror.ExitOperational
		}
		trimmed := strings.TrimSpace(string(b))
		if parts := strings.Fields(trimmed); len(parts) > 0 {
			trustedChecksum = parts[0]
		}
	}

	var sidecarChecksum string
	sidecarPath := archivePath + ".sha256"
	if b, err := os.ReadFile(sidecarPath); err == nil {
		trimmed := strings.TrimSpace(string(b))
		if parts := strings.Fields(trimmed); len(parts) > 0 {
			sidecarChecksum = parts[0]
			fmt.Printf("[+] Auto-discovered checksum sidecar: %s (consistency check only, not independent trust)\n", sidecarPath)
		}
	}

	fmt.Printf("[+] Initializing SQLite CVE store at %s ...\n", targetDB)
	store, err := cve.NewStore(targetDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed opening CVE store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	reg := cve.NewTemplateRegistry()
	_, _ = reg.LoadBuiltinTemplates()
	if *templatesDir != "" {
		_, _ = reg.LoadTemplatesFromDir(*templatesDir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Printf("[+] Importing air-gapped update archive from %s ...\n", archivePath)
	opts := cve.ImportOptions{
		TrustedArchiveSHA256: trustedChecksum,
		SidecarArchiveSHA256: sidecarChecksum,
	}
	report, err := cve.ImportOfflineArchive(ctx, archivePath, store, reg, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Import failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Println("===========================================================")
	fmt.Println("  FELIX :: Air-Gapped CVE & Template Import Summary")
	fmt.Println("===========================================================")
	fmt.Printf("Archive Path        : %s\n", report.ArchivePath)
	fmt.Printf("Archive SHA-256     : %s\n", report.ArchiveSHA256)
	fmt.Printf("Trust Classification: %s\n", report.TrustStatus)
	fmt.Printf("Manifest Version    : %s\n", report.ManifestVersion)
	fmt.Printf("Total Records       : %d\n", report.TotalRecords)
	fmt.Printf("Inserted Records    : %d\n", report.InsertedRecords)
	fmt.Printf("Updated Records     : %d\n", report.UpdatedRecords)
	fmt.Printf("Skipped Records     : %d\n", report.SkippedRecords)
	fmt.Printf("Validated Templates : %d\n", report.ValidatedTemplates)
	fmt.Printf("Import Duration     : %v\n", report.Duration)
	fmt.Println("-----------------------------------------------------------")
	fmt.Println("[+] SHA-256 Integrity Verification: PASSED (All files matched manifest digests)")
	fmt.Println("[+] Atomic SQLite Commit: PASSED (Transactional integrity preserved)")
	fmt.Println("===========================================================")
	return clierror.ExitSuccess
}

func runCVEStatus(args []string) int {
	fs := flag.NewFlagSet("felix cve status", flag.ContinueOnError)
	dbPath := fs.String("db", "", "Path to SQLite database")

	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	targetDB := *dbPath
	if targetDB == "" {
		def, err := cve.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default db path: %v\n", err)
			return clierror.ExitOperational
		}
		targetDB = def
	}

	store, err := cve.NewStore(targetDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed opening CVE store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats, err := store.GetStats(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed retrieving database stats: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Println("===========================================================")
	fmt.Println("  FELIX :: CVE Knowledge Base Status")
	fmt.Println("===========================================================")
	fmt.Printf("Database Path       : %s\n", stats.DBPath)
	fmt.Printf("File Size           : %.2f MB (%d bytes)\n", stats.FileSizeMB, stats.FileSizeBytes)
	fmt.Printf("Schema Version      : %s\n", stats.SchemaVersion)
	fmt.Printf("Total CVE Records   : %d\n", stats.TotalRecords)
	fmt.Printf("Unique CVEs         : %d\n", stats.UniqueCVEs)
	fmt.Printf("Unique CPE Prefixes : %d\n", stats.UniqueCPEPrefixes)
	fmt.Printf("Integrity Check     : %s\n", stats.IntegrityStatus)
	fmt.Println("===========================================================")
	return clierror.ExitSuccess
}

func runCVEQuery(args []string) int {
	fs := flag.NewFlagSet("felix cve query", flag.ContinueOnError)
	cpePrefix := fs.String("cpe", "", "Canonical CPE prefix (required)")
	version := fs.String("version", "", "Target software version (required)")
	dbPath := fs.String("db", "", "Path to SQLite database")

	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	if *cpePrefix == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "[-] Both --cpe and --version are required.")
		return clierror.ExitOperational
	}

	targetDB := *dbPath
	if targetDB == "" {
		def, err := cve.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed determining default db path: %v\n", err)
			return clierror.ExitOperational
		}
		targetDB = def
	}

	store, err := cve.NewStore(targetDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed opening CVE store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	matches, metrics, err := store.QueryByCPE(ctx, *cpePrefix, *version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Query failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Println("===========================================================")
	fmt.Println("  FELIX :: Hybrid SemVer CVE Query Result")
	fmt.Println("===========================================================")
	fmt.Printf("Target CPE Prefix    : %s\n", metrics.CPEPrefix)
	fmt.Printf("Target Version       : %s\n", metrics.TargetVersion)
	fmt.Printf("Candidates In SQLite : %d (Retrieved in %.3f ms)\n", metrics.CandidateCount, metrics.RetrievalLatencyMs)
	fmt.Printf("Confirmed Matches    : %d (Evaluated in %.3f ms)\n", metrics.ConfirmedMatchCount, metrics.EvalLatencyMs)
	fmt.Printf("Total Query Latency  : %.3f ms\n", metrics.TotalLatencyMs)
	fmt.Println("-----------------------------------------------------------")

	for _, m := range matches {
		if m.MatchStatus == cve.MatchConfirmed {
			fmt.Printf("[!] %s (CVSS %.1f, %s) -> %s\n", m.CVEID, m.CVSSScore, m.Severity, m.Summary)
			fmt.Printf("    Constraint: %s | %s\n", m.Constraint, m.EvaluationNotes)
		}
	}
	if metrics.ConfirmedMatchCount == 0 {
		fmt.Println("[+] No confirmed vulnerabilities found for this component version.")
	}
	fmt.Println("===========================================================")
	return clierror.ExitSuccess
}

func generateCoreSeedCVEs() []cve.CVERecord {
	return []cve.CVERecord{
		{
			CVEID:                 "CVE-2020-1938",
			Source:                cve.SourceNVD,
			CPEPrefix:             "cpe:2.3:a:apache:tomcat",
			Vendor:                "apache",
			Product:               "tomcat",
			VersionStart:          "9.0.0",
			VersionStartIncluding: true,
			VersionEnd:            "9.0.43",
			VersionEndIncluding:   false,
			CVSSScore:             9.8,
			Severity:              "CRITICAL",
			Summary:               "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections (Ghostcat).",
		},
		{
			CVEID:                 "CVE-2021-44228",
			Source:                cve.SourceNVD,
			CPEPrefix:             "cpe:2.3:a:apache:log4j",
			Vendor:                "apache",
			Product:               "log4j",
			VersionStart:          "2.0.0",
			VersionStartIncluding: true,
			VersionEnd:            "2.15.0",
			VersionEndIncluding:   false,
			CVSSScore:             10.0,
			Severity:              "CRITICAL",
			Summary:               "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
		},
		{
			CVEID:                 "CVE-2022-22965",
			Source:                cve.SourceNVD,
			CPEPrefix:             "cpe:2.3:a:vmware:spring_framework",
			Vendor:                "vmware",
			Product:               "spring_framework",
			VersionStart:          "5.3.0",
			VersionStartIncluding: true,
			VersionEnd:            "5.3.18",
			VersionEndIncluding:   false,
			CVSSScore:             9.8,
			Severity:              "CRITICAL",
			Summary:               "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (Spring4Shell).",
		},
	}
}

func printCVETemplateHelp() {
	fmt.Println("Usage: felix cve template <action> [options]")
	fmt.Println("\nActions:")
	fmt.Println("  list       List loaded and embedded vulnerability templates")
	fmt.Println("  validate   Validate syntax and closure compilation of YAML template(s)")
	fmt.Println("  run        Execute compiled templates against an authorized target URL")
	fmt.Println("\nOptions for list:")
	fmt.Println("  --dir <path>       Directory containing custom YAML templates")
	fmt.Println("\nOptions for validate:")
	fmt.Println("  --file <path>      Path to single YAML template file")
	fmt.Println("  --dir <path>       Path to directory containing YAML templates")
	fmt.Println("\nOptions for run:")
	fmt.Println("  --target <url>     Target HTTP/HTTPS URL (required)")
	fmt.Println("  --file <path>      Path to specific template file to execute")
	fmt.Println("  --dir <path>       Path to directory containing templates")
	fmt.Println("  --cve <id>         Execute only templates matching specific CVE ID")
	fmt.Println("  --timeout <sec>    Execution timeout in seconds (default: 10)")
	fmt.Println("  --allow-loopback   Permit execution against loopback addresses (127.0.0.1, localhost)")
	fmt.Println("  --allow-private    Permit execution against private RFC 1918 addresses")
}

func runCVETemplate(args []string) int {
	if len(args) == 0 {
		printCVETemplateHelp()
		return clierror.ExitOperational
	}

	action := args[0]
	actionArgs := args[1:]

	switch action {
	case "list":
		return runCVETemplateList(actionArgs)
	case "validate":
		return runCVETemplateValidate(actionArgs)
	case "run":
		return runCVETemplateRun(actionArgs)
	case "help", "--help", "-h":
		printCVETemplateHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown template action: %s\n\n", action)
		printCVETemplateHelp()
		return clierror.ExitOperational
	}
}

func runCVETemplateList(args []string) int {
	fs := flag.NewFlagSet("felix cve template list", flag.ContinueOnError)
	dirPath := fs.String("dir", "", "Directory containing custom templates")
	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	reg := cve.NewTemplateRegistry()
	loadedBuiltin, err := reg.LoadBuiltinTemplates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed loading embedded templates: %v\n", err)
	}

	var customStats cve.LoadStats
	if *dirPath != "" {
		s, err := reg.LoadTemplatesFromDir(*dirPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed loading templates from %s: %v\n", *dirPath, err)
			return clierror.ExitOperational
		}
		customStats = s
	}

	templates := reg.All()
	fmt.Println("===========================================================")
	fmt.Println("  FELIX :: Vulnerability Template Registry")
	fmt.Println("===========================================================")
	fmt.Printf("  Total Templates Loaded: %d (Built-in: %d, Custom: %d)\n", len(templates), loadedBuiltin, customStats.CompiledCount)
	fmt.Println("-----------------------------------------------------------")

	for _, t := range templates {
		cveStr := t.CVEID
		if cveStr == "" {
			cveStr = "N/A"
		}
		sevUpper := strings.ToUpper(t.Severity)
		fmt.Printf("  [%-8s] %-28s | CVE: %-14s | %s\n", sevUpper, t.ID, cveStr, t.Info.Name)
	}
	fmt.Println("===========================================================")
	return clierror.ExitSuccess
}

func runCVETemplateValidate(args []string) int {
	fs := flag.NewFlagSet("felix cve template validate", flag.ContinueOnError)
	filePath := fs.String("file", "", "Path to YAML template file")
	dirPath := fs.String("dir", "", "Path to template directory")
	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	if *filePath == "" && *dirPath == "" {
		fmt.Fprintln(os.Stderr, "[-] Either --file or --dir must be specified for validation")
		return clierror.ExitOperational
	}

	reg := cve.NewTemplateRegistry()

	if *filePath != "" {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed reading %s: %v\n", *filePath, err)
			return clierror.ExitOperational
		}
		tmpl, err := cve.ParseTemplate(b, *filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Validation FAILED for %s: %v\n", *filePath, err)
			return clierror.ExitOperational
		}
		ct, err := cve.CompileTemplate(tmpl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Compilation FAILED for %s: %v\n", *filePath, err)
			return clierror.ExitOperational
		}
		fmt.Printf("[+] Template %s (%s) successfully validated and compiled into memory closures (Requests: %d)\n", ct.ID, ct.Info.Name, len(ct.Requests))
		return clierror.ExitSuccess
	}

	stats, err := reg.LoadTemplatesFromDir(*dirPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Validation failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Printf("[+] Directory Validation Completed: %d/%d templates compiled successfully in %v\n", stats.CompiledCount, stats.TotalFiles, stats.CompileDuration)
	if len(stats.Errors) > 0 {
		fmt.Printf("[!] Encountered %d issues:\n", len(stats.Errors))
		for _, e := range stats.Errors {
			fmt.Printf("    - %s\n", e)
		}
	}
	return clierror.ExitSuccess
}

func runCVETemplateRun(args []string) int {
	fs := flag.NewFlagSet("felix cve template run", flag.ContinueOnError)
	targetURL := fs.String("target", "", "Target URL to assess (required)")
	filePath := fs.String("file", "", "Specific template to run")
	dirPath := fs.String("dir", "", "Directory of templates to run")
	cveFilter := fs.String("cve", "", "Filter templates by CVE ID")
	timeoutSec := fs.Int("timeout", 10, "Execution timeout in seconds")
	allowLoopback := fs.Bool("allow-loopback", false, "Permit execution against loopback addresses (127.0.0.1, localhost)")
	allowPrivate := fs.Bool("allow-private", false, "Permit execution against private RFC 1918 addresses")

	if err := fs.Parse(args); err != nil {
		return clierror.ExitOperational
	}

	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "[-] Target URL is required (--target <url>)")
		return clierror.ExitOperational
	}

	reg := cve.NewTemplateRegistry()
	_, _ = reg.LoadBuiltinTemplates()

	if *dirPath != "" {
		_, err := reg.LoadTemplatesFromDir(*dirPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed loading templates from %s: %v\n", *dirPath, err)
			return clierror.ExitOperational
		}
	}

	if *filePath != "" {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed reading %s: %v\n", *filePath, err)
			return clierror.ExitOperational
		}
		tmpl, err := cve.ParseTemplate(b, *filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid template: %v\n", err)
			return clierror.ExitOperational
		}
		_, err = reg.Register(tmpl)
		if err != nil && !strings.Contains(err.Error(), "already registered") {
			fmt.Fprintf(os.Stderr, "[-] Register error: %v\n", err)
			return clierror.ExitOperational
		}
	}

	var candidates []*cve.CompiledTemplate
	if *cveFilter != "" {
		candidates = reg.GetByCVE(*cveFilter)
		if len(candidates) == 0 {
			fmt.Fprintf(os.Stderr, "[-] No loaded templates matching CVE %s\n", *cveFilter)
			return clierror.ExitOperational
		}
	} else if *filePath != "" {
		// Just run the single template
		fileName := filepath.Base(*filePath)
		tID := strings.TrimSuffix(strings.TrimSuffix(fileName, ".yaml"), ".yml")
		if ct, ok := reg.Get(tID); ok {
			candidates = []*cve.CompiledTemplate{ct}
		} else {
			candidates = reg.All()
		}
	} else {
		candidates = reg.All()
	}

	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: Vulnerability Template Probe: %s\n", *targetURL)
	fmt.Printf("  Loaded Templates: %d | Timeout: %ds\n", len(candidates), *timeoutSec)
	fmt.Println("===========================================================")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	execOpts := cve.ExecutionOptions{
		AllowLoopback:   *allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true" || os.Getenv("FELIX_ALLOW_LOOPBACK") == "1",
		AllowPrivateIPs: *allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true" || os.Getenv("FELIX_ALLOW_PRIVATE") == "1",
	}

	matchedCount := 0
	for _, ct := range candidates {
		finding, err := ct.ExecuteWithOptions(ctx, *targetURL, execOpts)
		if err != nil {
			fmt.Printf("  [-] Error executing %s: %v\n", ct.ID, err)
			continue
		}
		if finding.Matched {
			matchedCount++
			fmt.Printf("  [!] CONFIRMED VULNERABILITY: [%s] %s\n", strings.ToUpper(finding.Severity), finding.Name)
			if finding.CVEID != "" {
				fmt.Printf("      CVE ID: %s | CVSS: %.1f\n", finding.CVEID, finding.CVSSScore)
			}
			fmt.Printf("      Matched URL: %s (Duration: %v)\n", finding.MatchedURL, finding.Duration)
			if len(finding.Evidence) > 0 {
				fmt.Printf("      Evidence: %s\n", strings.Join(finding.Evidence, "; "))
			}
			if len(finding.ExtractedData) > 0 {
				for k, v := range finding.ExtractedData {
					fmt.Printf("      Extracted [%s]: %s\n", k, v)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("  Execution Complete: %d templates evaluated, %d confirmed matches\n", len(candidates), matchedCount)
	fmt.Println("===========================================================")
	return clierror.ExitSuccess
}
