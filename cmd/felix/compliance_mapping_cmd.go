package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
	"felix/pkg/report"
)

func runComplianceMapping(args []string) int {
	if len(args) == 0 {
		printMappingHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "validate", "check":
		return runMappingValidate(subArgs)
	case "inspect", "show", "view":
		return runMappingInspect(subArgs)
	case "map", "run":
		return runMappingMap(subArgs)
	case "help", "--help", "-h":
		printMappingHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown mapping subcommand: %s\n\n", sub)
		printMappingHelp()
		return clierror.ExitOperational
	}
}

func printMappingHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance mapping <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  validate <file>      Validate a mapping ruleset JSON file (optionally against a catalog)")
	fmt.Println("  inspect <file>       Inspect mapping ruleset identity, version, rule count, and digest")
	fmt.Println("  map <file>           Map assessment findings to controls using catalog and mapping ruleset")
	fmt.Println("  help                 Display this help message")
	fmt.Println("\nOptions for 'validate':")
	fmt.Println("  --catalog <path>     Path to ControlCatalog file to verify cross-reference compatibility")
	fmt.Println("  --json               Output machine-readable JSON")
	fmt.Println("  --help, -h           Show help")
	fmt.Println("\nOptions for 'inspect':")
	fmt.Println("  --json               Output machine-readable JSON")
	fmt.Println("  --help, -h           Show help")
	fmt.Println("\nOptions for 'map':")
	fmt.Println("  --catalog <path>     Path to ControlCatalog JSON file (required)")
	fmt.Println("  --findings <path>    Path to findings JSON file ([]report.Finding or scan export)")
	fmt.Println("  --json               Output machine-readable JSON")
	fmt.Println("  --help, -h           Show help")
}

func runMappingValidate(args []string) int {
	var (
		filePath    string
		catalogPath string
		jsonOutput  bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--catalog", "-c":
			if i+1 < len(args) {
				catalogPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printMappingHelp()
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
		fmt.Fprintln(os.Stderr, "[-] Error: mapping ruleset file path is required")
		return clierror.ExitOperational
	}

	rs, err := compliance.LoadMappingRuleSet(filePath)
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
			fmt.Fprintf(os.Stderr, "[-] Error: mapping ruleset validation failed: %v\n", err)
		}
		return clierror.ExitOperational
	}

	var catalogIdentity string
	if catalogPath != "" {
		cat, err := compliance.LoadCatalog(catalogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: failed loading catalog for compatibility check: %v\n", err)
			return clierror.ExitOperational
		}
		catalogIdentity = cat.Identity()
		if err := compliance.ValidateMappingRuleSet(rs, cat); err != nil {
			if jsonOutput {
				res := map[string]any{
					"valid":            false,
					"file":             filePath,
					"catalog_file":     catalogPath,
					"catalog_identity": catalogIdentity,
					"error":            err.Error(),
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(res)
			} else {
				fmt.Fprintf(os.Stderr, "[-] Error: mapping ruleset is incompatible with catalog %s: %v\n", catalogIdentity, err)
			}
			return clierror.ExitOperational
		}
	}

	if jsonOutput {
		res := map[string]any{
			"valid":                  true,
			"file":                   filePath,
			"id":                     rs.ID,
			"version":                rs.Version,
			"target_catalog_id":      rs.TargetCatalogID,
			"target_catalog_version": rs.TargetCatalogVersion,
			"total_rules":            len(rs.Rules),
			"digest":                 rs.Digest(),
			"catalog_compatible":     catalogPath != "",
			"catalog_identity":       catalogIdentity,
			"limitations_notice":     compliance.MappingLimitationsNotice(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("=== FELIX Finding-to-Control Mapping Ruleset Validation ===\n")
		fmt.Printf("File:                   %s\n", filePath)
		fmt.Printf("RuleSet ID:             %s\n", rs.ID)
		fmt.Printf("Version:                %s\n", rs.Version)
		fmt.Printf("Target Catalog ID:      %s\n", rs.TargetCatalogID)
		if rs.TargetCatalogVersion != "" {
			fmt.Printf("Target Catalog Version: %s\n", rs.TargetCatalogVersion)
		}
		fmt.Printf("Total Rules:            %d\n", len(rs.Rules))
		fmt.Printf("Content Digest:         %s\n", rs.Digest())
		if catalogIdentity != "" {
			fmt.Printf("Catalog Compatibility:  VERIFIED against %s\n", catalogIdentity)
		}
		fmt.Printf("Validation Status:      VALID\n\n")
		fmt.Printf("[+] Mapping ruleset is structurally and referentially valid.\n\n")
		fmt.Printf("Notice:\n  %s\n", compliance.MappingLimitationsNotice())
	}

	return clierror.ExitSuccess
}

func runMappingInspect(args []string) int {
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
			printMappingHelp()
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
		fmt.Fprintln(os.Stderr, "[-] Error: mapping ruleset file path is required")
		return clierror.ExitOperational
	}

	rs, err := compliance.LoadMappingRuleSet(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading mapping ruleset: %v\n", err)
		return clierror.ExitOperational
	}

	// Categorize rules
	targetControls := make(map[string]int)
	ruleTypes := make(map[string]int)
	for _, r := range rs.Rules {
		targetControls[r.TargetControlID]++
		if r.SourceRuleID != "" {
			ruleTypes["source_rule_id"]++
		}
		if r.SourceCategory != "" {
			ruleTypes["source_category"]++
		}
	}

	if jsonOutput {
		res := map[string]any{
			"id":                     rs.ID,
			"version":                rs.Version,
			"identity":               rs.Identity(),
			"title":                  rs.Title,
			"target_catalog_id":      rs.TargetCatalogID,
			"target_catalog_version": rs.TargetCatalogVersion,
			"total_rules":            len(rs.Rules),
			"unique_target_controls": len(targetControls),
			"digest":                 rs.Digest(),
			"limitations_notice":     compliance.MappingLimitationsNotice(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("=== FELIX Mapping RuleSet Metadata ===\n")
		fmt.Printf("RuleSet ID:             %s\n", rs.ID)
		fmt.Printf("Version:                %s\n", rs.Version)
		fmt.Printf("Identity:               %s\n", rs.Identity())
		if rs.Title != "" {
			fmt.Printf("Title:                  %s\n", rs.Title)
		}
		fmt.Printf("Target Catalog ID:      %s\n", rs.TargetCatalogID)
		if rs.TargetCatalogVersion != "" {
			fmt.Printf("Target Catalog Version: %s\n", rs.TargetCatalogVersion)
		}
		fmt.Printf("Total Rules:            %d\n", len(rs.Rules))
		fmt.Printf("Unique Target Controls: %d\n", len(targetControls))
		fmt.Printf("Content Digest (SHA256):%s\n\n", rs.Digest())
		fmt.Printf("Limitations Notice:\n  %s\n", compliance.MappingLimitationsNotice())
	}

	return clierror.ExitSuccess
}

func runMappingMap(args []string) int {
	var (
		ruleSetPath  string
		catalogPath  string
		findingsPath string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--catalog", "-c":
			if i+1 < len(args) {
				catalogPath = args[i+1]
				i++
			}
		case "--findings", "-f":
			if i+1 < len(args) {
				findingsPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printMappingHelp()
			return clierror.ExitSuccess
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "[-] Unknown flag: %s\n", arg)
				return clierror.ExitOperational
			}
			if ruleSetPath == "" {
				ruleSetPath = arg
			}
		}
	}

	if ruleSetPath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: mapping ruleset file path is required")
		return clierror.ExitOperational
	}
	if catalogPath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --catalog <path> is required")
		return clierror.ExitOperational
	}

	rs, err := compliance.LoadMappingRuleSet(ruleSetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading mapping ruleset: %v\n", err)
		return clierror.ExitOperational
	}

	cat, err := compliance.LoadCatalog(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading catalog: %v\n", err)
		return clierror.ExitOperational
	}

	var findings []report.Finding
	if findingsPath != "" {
		f, err := loadFindingsFromFile(findingsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error loading findings from %q: %v\n", findingsPath, err)
			return clierror.ExitOperational
		}
		findings = f
	}

	engine := compliance.NewMappingEngine()
	result, err := engine.MapFindings(cat, rs, findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error executing finding-to-control mapping: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	} else {
		fmt.Printf("=== FELIX Finding-to-Control Mapping Results ===\n")
		fmt.Printf("Catalog Identity:       %s\n", result.CatalogIdentity)
		fmt.Printf("Catalog Digest:         %s\n", result.CatalogDigest)
		fmt.Printf("Mapping RuleSet:        %s\n", result.MappingRuleSetIdentity)
		fmt.Printf("Mapping RuleSet Digest: %s\n", result.MappingRuleSetDigest)
		fmt.Printf("Total Input Findings:   %d\n", len(findings))
		fmt.Printf("Mapped Findings:        %d\n", len(result.Mappings))
		fmt.Printf("Unmapped Findings:      %d\n", len(result.Unmapped))
		fmt.Printf("Referenced Controls:    %d\n\n", len(result.Coverage.ReferencedControls))

		if len(result.Mappings) > 0 {
			fmt.Printf("Mapped Relationships:\n")
			fmt.Printf("%-18s  %-12s  %-12s  %-14s  %s\n", "FINDING ID", "CONTROL ID", "CONFIDENCE", "RELATIONSHIP", "RULE ID")
			fmt.Printf("%-18s  %-12s  %-12s  %-14s  %s\n", "----------", "----------", "----------", "------------", "-------")
			for _, m := range result.Mappings {
				conf := fmt.Sprintf("%.2f", m.Confidence)
				if m.Confidence == 0 {
					conf = "1.00"
				}
				rel := string(m.Relationship)
				if rel == "" {
					rel = "direct"
				}
				fmt.Printf("%-18s  %-12s  %-12s  %-14s  %s\n", m.FindingID, m.ControlID, conf, rel, m.RuleID)
			}
			fmt.Println()
		}

		if len(result.Unmapped) > 0 {
			fmt.Printf("Unmapped Findings (%d):\n", len(result.Unmapped))
			for _, u := range result.Unmapped {
				fmt.Printf("  [-] %s (%s, category: %s): %s\n", u.FindingID, u.RuleID, u.Category, u.Reason)
			}
			fmt.Println()
		}

		fmt.Printf("Notice:\n  %s\n", result.LimitationsNotice)
	}

	return clierror.ExitSuccess
}

// loadFindingsFromFile safely parses findings from a JSON file.
// Supports both a raw JSON array ([]report.Finding) or a report container ({"findings": [...]}).
func loadFindingsFromFile(path string) ([]report.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty findings file")
	}

	// Try unmarshaling as raw array
	var list []report.Finding
	if err := json.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return list, nil
	}

	// Try unmarshaling as container object
	var container struct {
		Findings []report.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &container); err == nil && len(container.Findings) > 0 {
		return container.Findings, nil
	}

	return nil, fmt.Errorf("file does not contain valid findings JSON array or report envelope")
}
