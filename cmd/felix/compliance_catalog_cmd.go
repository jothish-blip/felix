package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runComplianceCatalog(args []string) int {
	if len(args) == 0 {
		printCatalogHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "validate", "check":
		return runCatalogValidate(subArgs)
	case "inspect", "show", "view":
		return runCatalogInspect(subArgs)
	case "controls", "list-controls", "ls":
		return runCatalogControls(subArgs)
	case "help", "--help", "-h":
		printCatalogHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown catalog subcommand: %s\n\n", sub)
		printCatalogHelp()
		return clierror.ExitOperational
	}
}

func printCatalogHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance catalog <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  validate <file>      Validate a control catalog JSON file for schema and semantic rules")
	fmt.Println("  inspect <file>       Inspect catalog metadata, control counts, and authority limitations")
	fmt.Println("  controls <file>      List and filter available controls defined in a catalog")
	fmt.Println("  help                 Display this help message")
	fmt.Println("\nOptions for 'validate' and 'inspect':")
	fmt.Println("  --json               Output machine-readable JSON")
	fmt.Println("  --help, -h           Show help")
	fmt.Println("\nOptions for 'controls':")
	fmt.Println("  --category <cat>     Filter controls by category")
	fmt.Println("  --severity <sev>     Filter controls by severity (LOW, MEDIUM, HIGH, CRITICAL)")
	fmt.Println("  --status <status>    Filter controls by status (active, deprecated, draft)")
	fmt.Println("  --limit <n>          Maximum number of controls to display")
	fmt.Println("  --json               Output machine-readable JSON")
	fmt.Println("  --help, -h           Show help")
}

func runCatalogValidate(args []string) int {
	var (
		filePath   string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printCatalogHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if filePath == "" {
				filePath = arg
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: catalog file path is required")
		return clierror.ExitOperational
	}

	cat, err := compliance.LoadCatalog(filePath)
	if err != nil {
		if jsonOutput {
			res := map[string]any{
				"valid": false,
				"file":  filePath,
				"error": err.Error(),
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		} else {
			fmt.Fprintf(os.Stderr, "[-] Error: catalog validation failed: %v\n", err)
		}
		return clierror.ExitOperational
	}

	if jsonOutput {
		res := map[string]any{
			"valid":              true,
			"file":               filePath,
			"id":                 cat.ID,
			"version":            cat.Version,
			"title":              cat.Title,
			"framework":          cat.Framework,
			"total_controls":     len(cat.Controls),
			"digest":             cat.Digest(),
			"limitations_notice": cat.LimitationsNotice(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("=== FELIX Control Catalog Validation ===\n")
		fmt.Printf("File:               %s\n", filePath)
		fmt.Printf("Catalog ID:         %s\n", cat.ID)
		fmt.Printf("Version:            %s\n", cat.Version)
		fmt.Printf("Title:              %s\n", cat.Title)
		if cat.Framework != "" {
			fmt.Printf("Framework:          %s\n", cat.Framework)
		}
		fmt.Printf("Total Controls:     %d\n", len(cat.Controls))
		fmt.Printf("Content Digest:     %s\n", cat.Digest())
		fmt.Printf("Validation Status:  VALID\n\n")
		fmt.Printf("[+] Catalog is structurally and semantically valid.\n\n")
		fmt.Printf("Notice:\n  %s\n", cat.LimitationsNotice())
	}

	return clierror.ExitSuccess
}

func runCatalogInspect(args []string) int {
	var (
		filePath   string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printCatalogHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if filePath == "" {
				filePath = arg
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: catalog file path is required")
		return clierror.ExitOperational
	}

	cat, err := compliance.LoadCatalog(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading catalog: %v\n", err)
		return clierror.ExitOperational
	}

	// Categorize controls
	categories := make(map[string]int)
	severities := make(map[string]int)
	statuses := make(map[string]int)
	for _, c := range cat.Controls {
		if c.Category != "" {
			categories[c.Category]++
		}
		if c.Severity != "" {
			severities[c.Severity]++
		}
		st := string(c.Status)
		if st == "" {
			st = "active"
		}
		statuses[st]++
	}

	if jsonOutput {
		res := map[string]any{
			"id":                 cat.ID,
			"version":            cat.Version,
			"title":              cat.Title,
			"framework":          cat.Framework,
			"description":        cat.Description,
			"source":             cat.Source,
			"total_controls":     len(cat.Controls),
			"categories":         categories,
			"severities":         severities,
			"statuses":           statuses,
			"digest":             cat.Digest(),
			"limitations_notice": cat.LimitationsNotice(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("=== FELIX Control Catalog Metadata ===\n")
		fmt.Printf("Catalog ID:         %s\n", cat.ID)
		fmt.Printf("Version:            %s\n", cat.Version)
		fmt.Printf("Identity:           %s\n", cat.Identity())
		fmt.Printf("Title:              %s\n", cat.Title)
		if cat.Framework != "" {
			fmt.Printf("Framework:          %s\n", cat.Framework)
		}
		if cat.Description != "" {
			fmt.Printf("Description:        %s\n", cat.Description)
		}
		if cat.Source != nil {
			if cat.Source.Name != "" {
				fmt.Printf("Authoritative Name: %s\n", cat.Source.Name)
			}
			if cat.Source.Publisher != "" {
				fmt.Printf("Publisher:          %s\n", cat.Source.Publisher)
			}
			if cat.Source.URL != "" {
				fmt.Printf("Source URL:         %s\n", cat.Source.URL)
			}
			if cat.Source.License != "" {
				fmt.Printf("License:            %s\n", cat.Source.License)
			}
		}
		fmt.Printf("Total Controls:     %d\n", len(cat.Controls))
		fmt.Printf("Digest (SHA-256):   %s\n", cat.Digest())

		if len(categories) > 0 {
			fmt.Printf("\nCategories (%d):\n", len(categories))
			for catName, count := range categories {
				fmt.Printf("  %-24s: %d\n", catName, count)
			}
		}

		if len(statuses) > 0 {
			fmt.Printf("\nLifecycle Statuses:\n")
			for st, count := range statuses {
				fmt.Printf("  %-12s: %d\n", st, count)
			}
		}

		fmt.Printf("\nAuthority & Accreditation Notice:\n")
		fmt.Printf("  %s\n", cat.LimitationsNotice())
	}

	return clierror.ExitSuccess
}

func runCatalogControls(args []string) int {
	var (
		filePath   string
		category   string
		severity   string
		status     string
		limit      int
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--category":
			if i+1 < len(args) {
				category = args[i+1]
				i++
			}
		case "--severity":
			if i+1 < len(args) {
				severity = strings.ToUpper(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--status":
			if i+1 < len(args) {
				status = strings.ToLower(strings.TrimSpace(args[i+1]))
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				limit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printCatalogHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if filePath == "" {
				filePath = arg
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: catalog file path is required")
		return clierror.ExitOperational
	}

	cat, err := compliance.LoadCatalog(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading catalog: %v\n", err)
		return clierror.ExitOperational
	}

	var filtered []compliance.Control
	for _, c := range cat.Controls {
		if category != "" && !strings.EqualFold(c.Category, category) {
			continue
		}
		if severity != "" && !strings.EqualFold(c.Severity, severity) {
			continue
		}
		if status != "" {
			cStatus := string(c.Status)
			if cStatus == "" {
				cStatus = "active"
			}
			if !strings.EqualFold(cStatus, status) {
				continue
			}
		}
		filtered = append(filtered, c)
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(filtered)
	} else {
		fmt.Printf("=== Controls in Catalog %s (%d of %d displayed) ===\n\n", cat.Identity(), len(filtered), len(cat.Controls))
		fmt.Printf("%-12s  %-8s  %-10s  %-20s  %s\n", "CONTROL ID", "STATUS", "SEVERITY", "CATEGORY", "TITLE")
		fmt.Printf("%-12s  %-8s  %-10s  %-20s  %s\n", "----------", "------", "--------", "--------", "-----")
		for _, c := range filtered {
			st := string(c.Status)
			if st == "" {
				st = "active"
			}
			sev := c.Severity
			if sev == "" {
				sev = "INFO"
			}
			catName := c.Category
			if len(catName) > 20 {
				catName = catName[:17] + "..."
			}
			fmt.Printf("%-12s  %-8s  %-10s  %-20s  %s\n", c.ID, st, sev, catName, c.Title)
		}
	}

	return clierror.ExitSuccess
}
