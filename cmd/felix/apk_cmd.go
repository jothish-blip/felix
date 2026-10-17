package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"felix/pkg/apk"
)

// runAPK executes the "felix apk" subcommand for APK intake, structural validation, and isolation.
func runAPK(args []string) int {
	var (
		extract       bool
		keepWorkspace bool
		jsonOutput    bool
		quiet         bool
		apkPath       string
		limits        = apk.DefaultLimits()
	)

	// Custom argument parser matching Felix CLI conventions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			printAPKHelp()
			return 0
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
			jsonOutput = true
			continue
		}
		if arg == "--quiet" || arg == "-q" || arg == "--silent" || arg == "-s" {
			quiet = true
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	opts := apk.IntakeOptions{
		Limits:  limits,
		Extract: extract,
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
		fmt.Println("  Status:                  PASS (Intake boundary verified; offline static-only)")
		fmt.Println("  Security Posture:        Unevaluated (APK security analysis pending)")
		fmt.Println("===========================================================")
	}

	return 0
}

func printAPKHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix apk [options] <path-to-apk>")
	fmt.Println("\nSafely validate and isolate Android APK packages for offline static analysis.")
	fmt.Println("\nOptions:")
	fmt.Println("  --extract                 Extract all safe entries to the isolated workspace")
	fmt.Println("  --keep-workspace, --keep  Retain the isolated temporary workspace directory on disk")
	fmt.Println("  --json                    Output machine-readable validation results as JSON")
	fmt.Println("  --quiet, -q               Suppress banner and verbose operational output")
	fmt.Println("  --max-compressed-size <n> Maximum allowed input APK file size in bytes (default: 200MB)")
	fmt.Println("  --max-entries <n>         Maximum allowed archive entries (default: 20000)")
	fmt.Println("  --help, -h                Show this help message")
}
