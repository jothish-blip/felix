package main

import (
	"fmt"
	"os"
	"strings"

	"felix/pkg/api"
	"felix/pkg/clierror"
)

// runTarget executes the "felix target" subcommand.
func runTarget(args []string) int {
	if len(args) == 0 {
		printTargetHelp()
		return clierror.ExitSuccess
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "validate":
		return runTargetValidate(subArgs)
	case "help", "--help", "-h":
		printTargetHelp()
		return clierror.ExitSuccess
	default:
		// If first arg ends with .yml or .yaml or starts with --profile, treat as validate
		if strings.HasPrefix(subCmd, "--profile") || strings.HasSuffix(strings.ToLower(subCmd), ".yml") || strings.HasSuffix(strings.ToLower(subCmd), ".yaml") {
			return runTargetValidate(args)
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown target subcommand: %s\n\n", subCmd)
		printTargetHelp()
		return clierror.ExitOperational
	}
}

func runTargetValidate(args []string) int {
	var profilePath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			printTargetValidateHelp()
			return clierror.ExitSuccess
		}
		if arg == "--profile" || arg == "-p" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprintf(os.Stderr, "[-] error: %s requires a file path argument\n", arg)
				return clierror.ExitOperational
			}
			i++
			profilePath = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			profilePath = strings.TrimPrefix(arg, "--profile=")
			continue
		}
		if strings.HasPrefix(arg, "-") {
			fmt.Fprintf(os.Stderr, "[-] error: unknown flag %q\n", arg)
			return clierror.ExitOperational
		}
		// Positional argument
		if profilePath == "" {
			profilePath = arg
		}
	}

	if profilePath == "" {
		fmt.Fprintf(os.Stderr, "[-] error: missing target profile file path (--profile <file> or felix target validate <file>)\n")
		return clierror.ExitOperational
	}

	profile, err := api.LoadTargetProfile(profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Target profile validation failed: %v\n", err)
		return clierror.ExitOperational
	}

	fmt.Printf("[+] Target profile is valid: %s\n", profilePath)
	if profile.Target.Name != "" {
		fmt.Printf("    Name:             %s\n", profile.Target.Name)
	}
	fmt.Printf("    Version:          %d\n", profile.Version)
	if len(profile.Target.BaseURLs) > 0 {
		fmt.Printf("    Base URLs:        %s\n", strings.Join(profile.Target.BaseURLs, ", "))
	}
	if len(profile.Target.AllowedHosts) > 0 {
		fmt.Printf("    Allowed Hosts:    %s\n", strings.Join(profile.Target.AllowedHosts, ", "))
	}
	fmt.Printf("    Safety Mode:      %s\n", profile.Safety.Mode)
	fmt.Printf("    Cross-Tenant:     %t\n", profile.Safety.AllowCrossTenantChecks)
	fmt.Printf("    Tenants:          %d declared\n", len(profile.Tenants))
	fmt.Printf("    Comparisons:      %d configured (enabled: %t)\n", len(profile.CrossTenantTests.Comparisons), profile.CrossTenantTests.Enabled)

	return clierror.ExitSuccess
}

func printTargetHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix target <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  validate    Validate syntax, schema, and safety bounds of a target profile")
	fmt.Println("\nFlags:")
	fmt.Println("  --help, -h  Show help for target command")
	fmt.Println("\nExamples:")
	fmt.Println("  felix target validate --profile felix.target.yml")
	fmt.Println("  felix target validate felix.target.yml")
}

func printTargetValidateHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix target validate [flags] [file]")
	fmt.Println("\nFlags:")
	fmt.Println("  --profile, -p   Path to target profile file (e.g. felix.target.yml)")
	fmt.Println("  --help, -h      Show help for validate subcommand")
}
