package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"felix/pkg/apk"
)

// runAPK executes the "felix apk" subcommand for APK intake, structural validation, and isolation.
func runAPK(args []string) int {
	var (
		extract          bool
		keepWorkspace    bool
		jsonOutput       bool
		quiet            bool
		analyzeManifest  bool
		analyzeArtifacts bool
		buildInventory   bool
		apkPath          string
		limits           = apk.DefaultLimits()
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

		if manifestRes == nil && artifactRes == nil && inventoryRes == nil {
			fmt.Println("  Status:                  PASS (Intake boundary verified; offline static-only)")
			fmt.Println("  Security Posture:        Unevaluated (Pass --analyze to run static security analysis)")
			fmt.Println("===========================================================")
		}
	}

	return 0
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
	fmt.Println("  --extract                     Extract all safe entries to the isolated workspace")
	fmt.Println("  --keep-workspace, --keep      Retain the isolated temporary workspace directory on disk")
	fmt.Println("  --json                        Output machine-readable validation results as JSON")
	fmt.Println("  --quiet, -q                   Suppress banner and verbose operational output")
	fmt.Println("  --max-compressed-size <n>     Maximum allowed input APK file size in bytes (default: 200MB)")
	fmt.Println("  --max-entries <n>             Maximum allowed archive entries (default: 20000)")
	fmt.Println("  --help, -h                    Show this help message")
}
