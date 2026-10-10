package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"felix/pkg/report"
)

// runReport executes the "felix report" subcommand.
// It loads an existing scan result file (JSON) and renders reports.
// ZERO network requests are performed by this command.
func runReport(args []string) int {
	fs := flag.NewFlagSet("felix report", flag.ContinueOnError)

	var (
		htmlPath   string
		jsonPath   string
		verbose    bool
		silent     bool
		commercial bool
	)

	fs.StringVar(&htmlPath, "html", "", "Export report to HTML file")
	fs.StringVar(&jsonPath, "json", "", "Export report to JSON file")
	fs.BoolVar(&verbose, "v", false, "Verbose terminal output")
	fs.BoolVar(&verbose, "verbose", false, "Verbose terminal output")
	fs.BoolVar(&silent, "s", false, "Silent / minimal terminal output")
	fs.BoolVar(&silent, "silent", false, "Silent / minimal terminal output")
	fs.BoolVar(&commercial, "commercial", false, "Render Commercial Report 2.0 specification")

	fs.Usage = func() {
		fmt.Println("Usage: felix report <scan-result.json> [options]")
		fmt.Println("\nGenerate assessment reports from an existing scan result file without re-scanning.")
		fmt.Println("Zero network requests are performed during report generation.")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "html", "json":
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
		return 2
	}

	for _, extra := range fs.Args() {
		clean := strings.TrimSpace(extra)
		if clean != "" {
			positional = append(positional, clean)
		}
	}

	if len(positional) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Error: missing scan result file\n")
		fs.Usage()
		return 2
	}

	scanResultPath := positional[0]
	if _, err := os.Stat(scanResultPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[-] Error: scan result file not found: %s\n", scanResultPath)
		return 2
	}

	rep, err := report.LoadReport(scanResultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: failed to parse scan result %s: %v\n", scanResultPath, err)
		return 2
	}

	// Export HTML if requested
	var exported []string
	if htmlPath != "" {
		if err := report.WriteHTML(rep, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to write HTML report to %s: %v\n", htmlPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  HTML: %s", htmlPath))
	}

	// Export JSON if requested
	if jsonPath != "" {
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to write JSON report to %s: %v\n", jsonPath, err)
			return 2
		}
		exported = append(exported, fmt.Sprintf("  JSON: %s", jsonPath))
	}

	// Print terminal output unless silent
	if !silent {
		if commercial {
			cr := report.BuildCommercialReport(rep)
			printCommercialReportSummary(cr, verbose)
		} else {
			printReportSummary(rep, verbose)
		}
		if len(exported) > 0 {
			fmt.Println("Generated Reports:")
			for _, exp := range exported {
				fmt.Println(exp)
			}
			fmt.Println()
		}
	}

	return determineExitCode(rep)
}

// printCommercialReportSummary prints Commercial Report 2.0 sections in terminal.
func printCommercialReportSummary(cr report.CommercialReport, verbose bool) {
	fmt.Println("===========================================================")
	fmt.Println(" FELIX :: COMMERCIAL SECURITY ASSESSMENT REPORT 2.0")
	fmt.Println("===========================================================")
	fmt.Printf("Report Ref:  %s\n", cr.ReportID)
	fmt.Printf("Target:      %s\n", cr.ExecutiveSummary.Target)
	fmt.Printf("Generated:   %s\n", cr.GeneratedAt)
	fmt.Printf("Risk Score:  %d/100 (%s)\n\n", cr.RiskOverview.RiskScore, cr.RiskOverview.RiskLevel)

	fmt.Println("1. EXECUTIVE SUMMARY:")
	fmt.Printf("  Status:    %s\n", cr.ExecutiveSummary.CompletionStatus)
	fmt.Printf("  Scope:     %s\n", cr.ExecutiveSummary.ScopeSummary)
	fmt.Printf("  Assets:    %d cataloged\n", cr.ExecutiveSummary.AssetsDiscoveredCount)
	fmt.Printf("  Verified:  %d confirmed exposures\n", cr.ExecutiveSummary.FindingsVerifiedCount)
	fmt.Printf("  Detected:  %d unverified candidates\n", cr.ExecutiveSummary.FindingsDetectedCount)
	fmt.Printf("  Observed:  %d observations\n", cr.ExecutiveSummary.ObservationsCount)
	fmt.Println()

	fmt.Println("2. ASSESSMENT SCOPE:")
	fmt.Printf("  Domains:   %s\n", strings.Join(cr.AssessmentScope.InScopeDomains, ", "))
	fmt.Printf("  Assessed:  %d endpoints (Provenance: %s)\n\n", cr.AssessmentScope.AssessedEndpointsCount, cr.AssessmentScope.Provenance)

	fmt.Printf("3. ATTACK SURFACE: %d assets\n\n", cr.AttackSurface.TotalAssets)

	fmt.Println("4. RISK OVERVIEW:")
	fmt.Printf("  Critical:  %d verified, %d detected\n", cr.RiskOverview.VerifiedCountsBySeverity["CRITICAL"], cr.RiskOverview.DetectedCountsBySeverity["CRITICAL"])
	fmt.Printf("  High:      %d verified, %d detected\n", cr.RiskOverview.VerifiedCountsBySeverity["HIGH"], cr.RiskOverview.DetectedCountsBySeverity["HIGH"])
	fmt.Printf("  Medium:    %d verified, %d detected\n", cr.RiskOverview.VerifiedCountsBySeverity["MEDIUM"], cr.RiskOverview.DetectedCountsBySeverity["MEDIUM"])
	fmt.Printf("  Low/Info:  %d verified, %d detected\n\n", cr.RiskOverview.VerifiedCountsBySeverity["LOW"], cr.RiskOverview.DetectedCountsBySeverity["LOW"])

	fmt.Printf("5. VERIFIED FINDINGS (%d):\n", len(cr.VerifiedFindings))
	if len(cr.VerifiedFindings) == 0 {
		fmt.Println("  (No verified findings confirmed)")
	} else {
		for _, vf := range cr.VerifiedFindings {
			fmt.Printf("  [%s] [%s] %s at %s\n", vf.Severity, vf.Verification.Status, vf.Title, vf.AffectedAsset)
			fmt.Printf("    Impact: %s\n", vf.SecurityImpact.Summary)
		}
	}
	fmt.Println()

	fmt.Printf("6. DETECTED FINDINGS (%d):\n", len(cr.DetectedFindings))
	if len(cr.DetectedFindings) == 0 {
		fmt.Println("  (No detected findings recorded)")
	} else {
		for _, df := range cr.DetectedFindings {
			fmt.Printf("  [%s] [%s] %s at %s\n", df.Severity, df.Verification.Status, df.Title, df.AffectedAsset)
			fmt.Printf("    Impact: %s\n", df.SecurityImpact.Summary)
		}
	}
	fmt.Println()

	fmt.Printf("7. OBSERVATIONS (%d):\n", len(cr.Observations))
	for _, obs := range cr.Observations {
		fmt.Printf("  [%s] %s (%s)\n", obs.ObservationType, obs.Title, obs.AffectedAsset)
	}
	fmt.Println()

	fmt.Println("8. TECHNICAL APPENDIX:")
	fmt.Printf("  Negative Verification Probes: %d\n", len(cr.TechnicalAppendix.NegativeVerificationOutcomes))
	fmt.Printf("  Finding Traceability Entries: %d\n", len(cr.TechnicalAppendix.FindingIndex))
	fmt.Printf("  Engines Executed:             %d\n", len(cr.TechnicalAppendix.EngineExecutionSummary))
	fmt.Println("  Note: Remediation recommendations are excluded (reserved for Stage 13).")
	fmt.Println()
}

// printReportSummary prints the unified assessment summary in the terminal.
func printReportSummary(rep report.Report, verbose bool) {
	fmt.Println("===========================================================")
	fmt.Println(" FELIX :: SECURITY ASSESSMENT REPORT")
	fmt.Println("===========================================================")
	if rep.Target != "" {
		fmt.Printf("Target:     %s\n", rep.Target)
	}
	if rep.Timestamp != "" {
		fmt.Printf("Timestamp:  %s\n", rep.Timestamp)
	}
	if rep.Duration != "" {
		fmt.Printf("Duration:   %s\n", rep.Duration)
	}
	fmt.Printf("Risk Score: %d/100 (%s)\n\n", rep.RiskScore, rep.RiskLevel)

	fmt.Println("Findings Summary:")
	fmt.Printf("  CRITICAL  %d\n", rep.Summary.CriticalCount)
	fmt.Printf("  HIGH      %d\n", rep.Summary.HighCount)
	fmt.Printf("  MEDIUM    %d\n", rep.Summary.MediumCount)
	fmt.Printf("  LOW       %d\n", rep.Summary.LowCount)
	fmt.Printf("  INFO      %d\n\n", rep.Summary.InfoCount)

	fmt.Println("Verification Status:")
	fmt.Printf("  VERIFIED     %d\n", rep.Summary.VerifiedCount)
	fmt.Printf("  DETECTED     %d\n", rep.Summary.DetectedCount)
	fmt.Printf("  OBSERVED     %d\n", rep.Summary.ObservedCount)
	if rep.Summary.NotVerifiedCount > 0 {
		fmt.Printf("  NOT_VERIFIED %d\n", rep.Summary.NotVerifiedCount)
	}
	if rep.Summary.NotExposedCount > 0 {
		fmt.Printf("  NOT_EXPOSED  %d\n", rep.Summary.NotExposedCount)
	}
	if rep.Summary.AttemptedCount > 0 {
		fmt.Printf("  Attempted:   %d (Verification Rate: %.1f%%)\n", rep.Summary.AttemptedCount, rep.Summary.VerificationRateAttempted)
	}
	if rep.Summary.BlockedCount > 0 {
		fmt.Printf("  Blocked:     %d (Safety Boundaries)\n", rep.Summary.BlockedCount)
	}
	if rep.Summary.InconclusiveCount > 0 {
		fmt.Printf("  Inconclusive:%d\n", rep.Summary.InconclusiveCount)
	}
	fmt.Println()

	if len(rep.SecurityStories) > 0 {
		fmt.Printf("Correlated Security Stories (%d):\n", len(rep.SecurityStories))
		fmt.Println("────────────────────────────────────────")
		for _, s := range rep.SecurityStories {
			bonus := ""
			if s.RiskContribution > 0 {
				bonus = fmt.Sprintf(" (+%d Risk Pts)", s.RiskContribution)
			}
			fmt.Printf("[%s] %s%s\n", s.Severity, s.Title, bonus)
			if s.Summary != "" {
				fmt.Printf("  Summary:          %s\n", s.Summary)
			}
			fmt.Printf("  Impact:           %s\n", s.Impact)
			if s.InvestigateFirst != "" {
				fmt.Printf("  Investigate First: %s\n", s.InvestigateFirst)
			}
			fmt.Printf("  Remediation:      %s\n\n", s.Remediation)
		}
	}

	if len(rep.AttackPaths) > 0 {
		fmt.Printf("Correlated Attack Paths (%d):\n", len(rep.AttackPaths))
		fmt.Println("────────────────────────────────────────")
		for _, p := range rep.AttackPaths {
			synth := ""
			if p.SyntheticFixture {
				synth = "[SYNTHETIC FIXTURE] "
			}
			fmt.Printf("[%s] [%s] %s%s (%d/100, Conf: %s)\n", p.Status, p.CombinedRiskLevel, synth, p.Title, p.CombinedRiskScore, p.Confidence)
			if p.TargetAsset != "" {
				fmt.Printf("  Target Asset:     %s\n", p.TargetAsset)
			}
			if p.EntryPoint != "" {
				fmt.Printf("  Entry Point:      %s\n", p.EntryPoint)
			}
			if p.PrimaryWeakness != "" {
				fmt.Printf("  Primary Weakness: %s\n", p.PrimaryWeakness)
			}
			if p.TerminalImpact != "" {
				fmt.Printf("  Terminal Impact:  %s\n", p.TerminalImpact)
			}
			if p.RiskRationale != "" {
				fmt.Printf("  Risk Rationale:   %s\n", p.RiskRationale)
			}
			if len(p.Transitions) > 0 && verbose {
				fmt.Println("  Validated Transitions:")
				for _, tr := range p.Transitions {
					fmt.Printf("    ↳ %s\n", tr)
				}
			}
			if len(p.Assumptions) > 0 {
				fmt.Printf("  Assumptions:      %s\n", strings.Join(p.Assumptions, "; "))
			}
			if len(p.MissingEvidence) > 0 {
				fmt.Printf("  Missing Evidence: %s\n", strings.Join(p.MissingEvidence, "; "))
			}
			if p.Remediation != "" {
				fmt.Printf("  Remediation:      %s\n", p.Remediation)
			}
			fmt.Println()
		}
	}

	if len(rep.TopPriorities) > 0 {
		fmt.Println("Top Priorities:")
		fmt.Println("────────────────────────────────────────")
		for _, p := range rep.TopPriorities {
			fmt.Printf("[%s] %s\n", p.Severity, p.Title)
			fmt.Printf("  Confidence:   %s\n", p.Confidence)
			if p.Verification.Status != "" {
				fmt.Printf("  Verification: %s\n", p.Verification.Status)
			}
			loc := p.Endpoint
			if p.EvidenceDetails.Location != "" {
				loc = p.EvidenceDetails.Location
			}
			if loc != "" {
				fmt.Printf("  Location:     %s\n", loc)
			}
			if p.EvidenceDetails.NegativeEvidence != "" {
				fmt.Printf("  Negative Note:%s\n", p.EvidenceDetails.NegativeEvidence)
			}
			if p.Remediation != "" {
				fmt.Printf("  Remediation:  %s\n", p.Remediation)
			}
			fmt.Println()
		}
	}

	if verbose && len(rep.Findings) > 0 {
		fmt.Println("All Detailed Findings:")
		fmt.Println("────────────────────────────────────────")
		for _, f := range rep.Findings {
			fmt.Printf("[%s] [%s] %s\n", f.Severity, f.Category, f.Title)
			loc := f.Endpoint
			if f.EvidenceDetails.Location != "" {
				loc = f.EvidenceDetails.Location
			}
			if loc != "" {
				fmt.Printf("  Location:     %s\n", loc)
			}
			if f.Verification.Status != "" {
				fmt.Printf("  Status:       %s\n", f.Verification.Status)
			}
			if f.Remediation != "" {
				fmt.Printf("  Remediation:  %s\n", f.Remediation)
			}
			fmt.Println()
		}
	}
}

// determineExitCode returns:
// 0: Clean scan / INFO only findings
// 1: Actionable findings requiring attention (Low, Medium, High, Critical)
// 2: Handled upstream on runtime / usage error
func determineExitCode(rep report.Report) int {
	if rep.Summary.CriticalCount > 0 || rep.Summary.HighCount > 0 || rep.Summary.MediumCount > 0 || rep.Summary.LowCount > 0 {
		return 1
	}
	return 0
}
