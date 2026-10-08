package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"felix/pkg/update"
)

func runUpdate(args []string) int {
	var (
		checkOnly     bool
		force         bool
		dryRun        bool
		targetVersion string
		repo          string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			printUpdateHelp()
			return 0
		case arg == "--check" || arg == "-c":
			checkOnly = true
		case arg == "--force" || arg == "-f":
			force = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--version" || arg == "-v":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a version argument (e.g. 1.0.1)\n", arg)
				return 2
			}
			i++
			targetVersion = args[i]
		case strings.HasPrefix(arg, "--version="):
			targetVersion = strings.TrimPrefix(arg, "--version=")
		case arg == "--repo":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: --repo requires an owner/repository argument\n")
				return 2
			}
			i++
			repo = args[i]
		case strings.HasPrefix(arg, "--repo="):
			repo = strings.TrimPrefix(arg, "--repo=")
		default:
			fmt.Fprintf(os.Stderr, "[-] error: unknown argument %q\n\n", arg)
			printUpdateHelp()
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	u := update.NewUpdater(repo, Version)

	// Mode 1: Check-only mode (--check)
	if checkOnly {
		fmt.Printf("[*] Checking for updates (current version: %s)...\n", Version)
		res, err := u.Checker.CheckLatest(ctx, Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Update check failed: %v\n", err)
			return 2
		}

		fmt.Printf("Current version: %s\n", res.CurrentVersion)
		fmt.Printf("Latest version:  %s\n", res.LatestVersion)

		if res.UpdateAvailable {
			fmt.Println("\nUpdate available. Run 'felix update' to upgrade.")
			if res.ReleaseURL != "" {
				fmt.Printf("Release details: %s\n", res.ReleaseURL)
			}
		} else {
			fmt.Printf("\nFelix %s is up to date.\n", res.CurrentVersion)
		}
		return 0
	}

	// Mode 2: Interactive or automated update execution
	fmt.Printf("[*] Starting Felix secure update (current: v%s)...\n", Version)

	opts := update.UpdateOptions{
		TargetVersion: targetVersion,
		Force:         force,
		DryRun:        dryRun,
		Progress: func(step, details string) {
			fmt.Printf(" [%-8s] %s\n", step, details)
		},
	}

	result, err := u.Update(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[-] Felix update failed.\n\nReason:\n%v\n", err)
		if strings.Contains(err.Error(), "rolled back") {
			fmt.Fprintln(os.Stderr, "\nThe previous Felix installation was safely restored.")
		}
		return 2
	}

	if result.PreviousVersion == result.UpdatedVersion && !force {
		fmt.Printf("\n[+] Felix is already at the latest version (%s). No changes made.\n", result.UpdatedVersion)
		return 0
	}

	if dryRun {
		fmt.Printf("\n[+] Dry run successful. Verified release v%s ready for installation.\n", result.UpdatedVersion)
		return 0
	}

	fmt.Printf("\n[+] Felix successfully updated to v%s (%s)\n", result.UpdatedVersion, result.TargetPlatform)
	fmt.Println("Run 'felix doctor' to verify system runtime readiness.")
	return 0
}

func printUpdateHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix update [options]")
	fmt.Println("\nCheck for and install official Felix release updates with cryptographic integrity verification.")
	fmt.Println("\nOptions:")
	fmt.Println("  --check, -c         Check for available updates without downloading or installing")
	fmt.Println("  --version <version> Install a specific release version (e.g. 1.0.1)")
	fmt.Println("  --force, -f         Force installation even if already on the target version or downgrading")
	fmt.Println("  --dry-run           Download and verify the update package without replacing the executable")
	fmt.Println("  --repo <owner/repo> Override the update source repository [default: jothish-blip/felix]")
	fmt.Println("  --help, -h          Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  felix update --check")
	fmt.Println("  felix update")
	fmt.Println("  felix update --version 1.0.1")
}
