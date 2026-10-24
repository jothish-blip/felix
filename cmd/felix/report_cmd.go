package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/config"
	"felix/pkg/policy"
	"felix/pkg/report"
	"felix/pkg/ui"

	"github.com/mattn/go-isatty"
)

// runReport executes the "felix report" subcommand.
// It loads an existing scan result file (JSON) and renders reports.
// ZERO network requests are performed by this command.
func runReport(args []string) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		printReportHelp()
		return clierror.ExitSuccess
	}

	fs := flag.NewFlagSet("felix report", flag.ContinueOnError)

	var (
		htmlPath       string
		jsonPath       string
		sarifPath      string
		exportPath     string
		policyPath     string
		reproduceChain string
		outputPath     string
		overwrite      bool
		verbose        bool
		silent         bool
		commercial     bool
	)

	fs.StringVar(&htmlPath, "html", "", "Export report to HTML file")
	fs.StringVar(&jsonPath, "json", "", "Export report to JSON file")
	fs.StringVar(&sarifPath, "sarif", "", "Export report to SARIF 2.1.0 file")
	fs.StringVar(&exportPath, "export", "", "Export report to specified path (.html, .json, or .sarif)")
	fs.StringVar(&policyPath, "policy", "", "Path to security threshold policy file for evaluation")
	fs.StringVar(&reproduceChain, "reproduce-chain", "", "Chain ID to export Proof-of-Exploit reproduction script for")
	fs.StringVar(&outputPath, "output", "", "Output filepath for generated reproduction script")
	fs.BoolVar(&overwrite, "overwrite", false, "Overwrite output script if file already exists")
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
				case "html", "json", "sarif", "policy", "export", "reproduce-chain", "output":
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
		if errors.Is(err, flag.ErrHelp) {
			return clierror.ExitSuccess
		}
		return clierror.ExitOperational
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

	if err := report.ValidateReportIntegrity(rep); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: scan result integrity check failed: %v\n", err)
		return 2
	}

	// Resolve policy path: explicit CLI flag takes precedence over config
	var pol *policy.ThresholdPolicy
	cfgStore, _ := config.LoadWithEnv("")
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

	// Recalculate risk score and risk level to reflect current deterministic scoring model
	report.RecalculateReportRisk(&rep)

	// Export Proof-of-Exploit Reproduction Script if requested
	if reproduceChain != "" {
		var targetPath *report.AttackPathSummary
		var matchCount int
		for i := range rep.AttackPaths {
			p := &rep.AttackPaths[i]
			if strings.EqualFold(p.ID, reproduceChain) {
				targetPath = p
				matchCount++
			}
		}

		if matchCount == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: attack path %q not found in scan result %s\n", reproduceChain, scanResultPath)
			if len(rep.AttackPaths) > 0 {
				fmt.Fprintln(os.Stderr, "    Available attack path IDs:")
				for _, p := range rep.AttackPaths {
					fmt.Fprintf(os.Stderr, "      - %s (%s)\n", p.ID, p.Title)
				}
			}
			return 2
		}

		outScript, err := report.WriteReproductionScript(*targetPath, rep.Findings, report.ReproductionOptions{
			OutputFile: outputPath,
			Overwrite:  overwrite,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: failed to export reproduction script: %v\n", err)
			return 2
		}

		fmt.Printf("[+] Standalone reproduction script exported: %s\n", outScript)
		fmt.Printf("    Chain ID:     %s\n", targetPath.ID)
		fmt.Printf("    Title:        %s\n", targetPath.Title)
		fmt.Printf("    Safety Mode:  Strict Non-Destructive\n")
		fmt.Printf("    Run:          TARGET_ORIGIN=https://<target> ./%s\n", filepath.Base(outScript))
		return 0
	}

	// Export HTML if requested
	var exported []string
	var exportErrs []error
	if htmlPath != "" {
		if commercial {
			cr := report.BuildCommercialReport(rep)
			if err := report.WriteCommercialHTML(cr, htmlPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write Commercial HTML report to %s: %v\n", htmlPath, err)
				exportErrs = append(exportErrs, err)
			} else {
				exported = append(exported, fmt.Sprintf("  Commercial HTML: %s", htmlPath))
			}
		} else {
			if err := report.WriteHTML(rep, htmlPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write HTML report to %s: %v\n", htmlPath, err)
				exportErrs = append(exportErrs, err)
			} else {
				exported = append(exported, fmt.Sprintf("  HTML: %s", htmlPath))
			}
		}
	}

	// Export JSON if requested
	if jsonPath != "" {
		if commercial {
			cr := report.BuildCommercialReport(rep)
			if err := report.WriteCommercialJSON(cr, jsonPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write Commercial JSON report to %s: %v\n", jsonPath, err)
				exportErrs = append(exportErrs, err)
			} else {
				exported = append(exported, fmt.Sprintf("  Commercial JSON: %s", jsonPath))
			}
		} else {
			if err := report.WriteJSON(rep, jsonPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write JSON report to %s: %v\n", jsonPath, err)
				exportErrs = append(exportErrs, err)
			} else {
				exported = append(exported, fmt.Sprintf("  JSON: %s", jsonPath))
			}
		}
	}

	// Export SARIF if requested
	if sarifPath != "" {
		if err := report.WriteSARIF(rep, sarifPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to write SARIF report to %s: %v\n", sarifPath, err)
			exportErrs = append(exportErrs, err)
		} else {
			exported = append(exported, fmt.Sprintf("  SARIF 2.1.0: %s", sarifPath))
		}
	}

	// Export via canonical --export flag (format inferred by extension: .html, .sarif, or .json)
	if exportPath != "" {
		ext := strings.ToLower(filepath.Ext(exportPath))
		switch ext {
		case ".sarif":
			if err := report.WriteSARIF(rep, exportPath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write SARIF report to %s: %v\n", exportPath, err)
				exportErrs = append(exportErrs, err)
			} else {
				exported = append(exported, fmt.Sprintf("  SARIF 2.1.0: %s", exportPath))
			}
		case ".html", ".htm":
			if commercial {
				cr := report.BuildCommercialReport(rep)
				if err := report.WriteCommercialHTML(cr, exportPath); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to write Commercial HTML report to %s: %v\n", exportPath, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  Commercial HTML: %s", exportPath))
				}
			} else {
				if err := report.WriteHTML(rep, exportPath); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to write HTML report to %s: %v\n", exportPath, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  HTML: %s", exportPath))
				}
			}
		default:
			if commercial {
				cr := report.BuildCommercialReport(rep)
				if err := report.WriteCommercialJSON(cr, exportPath); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to write Commercial JSON report to %s: %v\n", exportPath, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  Commercial JSON: %s", exportPath))
				}
			} else {
				if err := report.WriteJSON(rep, exportPath); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to write JSON report to %s: %v\n", exportPath, err)
					exportErrs = append(exportErrs, err)
				} else {
					exported = append(exported, fmt.Sprintf("  JSON: %s", exportPath))
				}
			}
		}
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

	reportStatus := rep.CompletionStatus
	if reportStatus == "" {
		reportStatus = "COMPLETED"
	}

	var policyDecision *policy.EvaluationDecision
	var policyErr error
	if pol != nil {
		ctx := policy.EvaluationContext{
			Status: reportStatus,
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
			if !silent {
				fmt.Print(policy.FormatDecisionSummary(decision))
			}
		}
	}

	if pol != nil {
		hasViolation := policyDecision != nil && !policyDecision.Passed
		cls := clierror.ClassifyAssessment(reportStatus, nil, hasViolation, policyErr, exportErrs...)
		return cls.ExitCode()
	}

	// No policy configured
	if len(exportErrs) > 0 {
		return clierror.ExitOperational
	}
	return determineExitCode(rep)
}

func printReportHelp() {
	fmt.Println("Usage: felix report <scan-result.json> [options]")
	fmt.Println("\nGenerate assessment reports from an existing scan result file without re-scanning.")
	fmt.Println("Zero network requests are performed during report generation.")
	fmt.Println("\nOptions:")
	fmt.Println("  --html <path>         Export report to HTML file")
	fmt.Println("  --json <path>         Export report to JSON file")
	fmt.Println("  --sarif <path>        Export report to SARIF 2.1.0 file")
	fmt.Println("  --export <path>       Export report to path by extension (.html, .json, .sarif)")
	fmt.Println("  --policy <path>       Evaluate security threshold policy against report")
	fmt.Println("  --commercial          Render Commercial Report 2.0 specification")
	fmt.Println("  -v, --verbose         Verbose terminal output")
	fmt.Println("  -s, --silent          Silent / minimal terminal output")
}

// printCommercialReportSummary prints Commercial Report 2.0 sections in terminal.
func printCommercialReportSummary(cr report.CommercialReport, verbose bool) {
	isTerm := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	cardCfg := ui.DefaultCardConfig(isTerm)
	colored := !cardCfg.NoColor

	cardData := ui.CommercialSummaryCardData{
		ReportID:        cr.ReportID,
		Target:          cr.ExecutiveSummary.Target,
		GeneratedAt:     cr.GeneratedAt,
		CompletionState: cr.ExecutiveSummary.CompletionStatus,
		RiskScore:       cr.RiskOverview.RiskScore,
		RiskLevel:       cr.RiskOverview.RiskLevel,
		ScoreAvailable:  cr.ExecutiveSummary.RiskScoreAvailable,
		AssetsCount:     cr.AttackSurface.TotalAssets,
		VerifiedCount:   cr.ExecutiveSummary.FindingsVerifiedCount,
		DetectedCount:   cr.ExecutiveSummary.FindingsDetectedCount,
		ObservedCount:   cr.ExecutiveSummary.ObservationsCount,
		NegativeProbes:  len(cr.TechnicalAppendix.NegativeVerificationOutcomes),
	}
	fmt.Print(ui.RenderCommercialSummaryCard(cardData, cardCfg))
	fmt.Println()

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
			fmt.Printf("  %s %s %s at %s\n", ui.SeverityBadge(vf.Severity, colored), ui.VerificationBadge(string(vf.Verification.Status), colored), vf.Title, vf.AffectedAsset)
			fmt.Printf("    Impact: %s\n", vf.SecurityImpact.Summary)
		}
	}
	fmt.Println()

	fmt.Printf("6. DETECTED FINDINGS (%d):\n", len(cr.DetectedFindings))
	if len(cr.DetectedFindings) == 0 {
		fmt.Println("  (No detected findings recorded)")
	} else {
		for _, df := range cr.DetectedFindings {
			fmt.Printf("  %s %s %s at %s\n", ui.SeverityBadge(df.Severity, colored), ui.VerificationBadge(string(df.Verification.Status), colored), df.Title, df.AffectedAsset)
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
	isTerm := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	cardCfg := ui.DefaultCardConfig(isTerm)
	colored := !cardCfg.NoColor

	cardData := ui.SummaryCardData{
		Target:            rep.Target,
		CompletionStatus:  rep.CompletionStatus,
		Timestamp:         rep.Timestamp,
		Duration:          rep.Duration,
		RiskScore:         rep.RiskScore,
		RiskLevel:         rep.RiskLevel,
		ScoreAvailable:    rep.RiskScoreAvailable,
		CriticalCount:     rep.Summary.CriticalCount,
		HighCount:         rep.Summary.HighCount,
		MediumCount:       rep.Summary.MediumCount,
		LowCount:          rep.Summary.LowCount,
		InfoCount:         rep.Summary.InfoCount,
		VerifiedCount:     rep.Summary.VerifiedCount,
		DetectedCount:     rep.Summary.DetectedCount,
		ObservedCount:     rep.Summary.ObservedCount,
		NotExposedCount:   rep.Summary.NotExposedCount,
		BlockedCount:      rep.Summary.BlockedCount,
		InconclusiveCount: rep.Summary.InconclusiveCount,
	}
	fmt.Print(ui.RenderExecutiveSummaryCard(cardData, cardCfg))
	fmt.Println()

	if rep.ChangeSummary != nil {
		fmt.Println("Security Posture Delta & Assessment History:")
		baseRef := rep.ChangeSummary.BaselineExecutionID
		if baseRef == "" {
			baseRef = "[Initial Baseline]"
		}
		fmt.Printf("  Baseline:    %s\n", baseRef)
		fmt.Printf("  Status:      %s\n", rep.ChangeSummary.ComparisonStatus)
		fmt.Printf("  Deltas:      +%d New, -%d Resolved, %d Persistent\n",
			rep.ChangeSummary.Counts.New,
			rep.ChangeSummary.Counts.Resolved,
			rep.ChangeSummary.Counts.Persistent,
		)
		if rep.ChangeSummary.Counts.SeverityIncreased > 0 || rep.ChangeSummary.Counts.SeverityDecreased > 0 {
			fmt.Printf("  Severity:    ▲ %d Increased, ▼ %d Decreased\n",
				rep.ChangeSummary.Counts.SeverityIncreased,
				rep.ChangeSummary.Counts.SeverityDecreased,
			)
		}
		if rep.ChangeSummary.Counts.Unknown > 0 {
			fmt.Printf("  Unverified:  ? %d\n", rep.ChangeSummary.Counts.Unknown)
		}
		fmt.Println()
	}

	if frameworks := rep.DetectedFrameworks(); len(frameworks) > 0 {
		fmt.Printf("Backend Frameworks & Runtimes (%d):\n", len(frameworks))
		fmt.Println("────────────────────────────────────────")
		for _, fw := range frameworks {
			verStr := ""
			if fw.Version != "" {
				verStr = " v" + fw.Version
			}
			fmt.Printf("  • %s%s: %d findings [%s]\n", fw.Name, verStr, fw.TotalFindings, fw.Status)
		}
		fmt.Println()
	}

	if len(rep.SecurityStories) > 0 {
		fmt.Printf("Correlated Security Stories (%d):\n", len(rep.SecurityStories))
		fmt.Println("────────────────────────────────────────")
		for _, s := range rep.SecurityStories {
			bonus := ""
			if s.RiskContribution > 0 {
				bonus = fmt.Sprintf(" (+%d Risk Pts)", s.RiskContribution)
			}
			fmt.Printf("%s %s%s\n", ui.SeverityBadge(s.Severity, colored), s.Title, bonus)
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
			fmt.Printf("[%s] %s %s%s (%d/100, Conf: %s)\n", p.Status, ui.SeverityBadge(p.CombinedRiskLevel, colored), synth, p.Title, p.CombinedRiskScore, p.Confidence)
			if len(p.GraphNodes) > 0 {
				var nodeLabels []string
				for _, n := range p.GraphNodes {
					nodeLabels = append(nodeLabels, "["+n.ID+"]")
				}
				fmt.Printf("  Chain:            %s\n", strings.Join(nodeLabels, " ➔ "))
			}
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
			if len(p.GraphEdges) > 0 && verbose {
				fmt.Println("  Validated Transitions:")
				for _, edge := range p.GraphEdges {
					ruleTag := string(edge.RuleCode)
					if ruleTag == "" {
						ruleTag = "TRANSITION"
					}
					statusTag := edge.ValidationStatus
					if statusTag == "" {
						statusTag = "CONFIRMED"
					}
					confStr := edge.Confidence
					if confStr == "" {
						confStr = "HIGH"
					}
					fmt.Printf("    ↳ [%s/%s] %s ➔ %s (Conf: %s)\n", ruleTag, statusTag, edge.SourceID, edge.TargetID, confStr)
					if edge.Explanation != "" {
						fmt.Printf("      Explanation: %s\n", edge.Explanation)
					}
				}
			} else if len(p.Transitions) > 0 && verbose {
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
	} else if verbose {
		fmt.Println("[*] No evidence-supported multi-hop attack paths established.")
	}

	if rep.RemediationBottlenecks != nil && rep.RemediationBottlenecks.PrimaryRecommendation != nil {
		bn := rep.RemediationBottlenecks
		best := bn.PrimaryRecommendation
		fmt.Println("Priority Remediation Bottleneck:")
		fmt.Println("────────────────────────────────────────────────────────────")
		fmt.Printf("  Candidate:        %s\n", best.Name)
		if best.Component != "" {
			fmt.Printf("  Component:        %s\n", best.Component)
		}
		if best.Endpoint != "" {
			fmt.Printf("  Endpoint:         %s\n", best.Endpoint)
		}
		fmt.Printf("  Chains Disrupted: %d of %d (%.1f%%)\n", best.DisruptedCount, best.TotalChains, best.DisruptionPercentage)
		fmt.Printf("  Residual Chains:  %d\n", best.ResidualCount)
		fmt.Printf("  Actionable Fix:   %s\n", best.ActionableFix)
		if bn.MinimumCutSize > 0 {
			fmt.Printf("  Min Vertex Cut:   %d node(s) (%s)\n", bn.MinimumCutSize, strings.Join(bn.MinimumCutNodes, ", "))
		}
		fmt.Println()
	}

	if len(rep.TopPriorities) > 0 {
		fmt.Println("Top Actionable Priorities:")
		fmt.Println("────────────────────────────────────────────────────────────")
		for _, p := range rep.TopPriorities {
			fmt.Printf("%s %s\n", ui.SeverityBadge(p.Severity, colored), p.Title)
			fmt.Printf("  Confidence:     %s\n", p.Confidence)
			if p.Verification.Status != "" {
				fmt.Printf("  Verification:   %s\n", ui.VerificationBadge(string(p.Verification.Status), colored))
			}
			loc := p.Endpoint
			if p.EvidenceDetails.Location != "" {
				loc = p.EvidenceDetails.Location
			}
			if loc != "" {
				fmt.Printf("  Location:       %s\n", loc)
			}
			if p.EvidenceDetails.NegativeEvidence != "" {
				fmt.Printf("  Defensive Note: %s\n", p.EvidenceDetails.NegativeEvidence)
			}
			if p.Remediation != "" {
				fmt.Printf("  Remediation:    %s\n", p.Remediation)
			}
			fmt.Println()
		}
	}

	if verbose && len(rep.Findings) > 0 {
		fmt.Println("All Detailed Findings:")
		fmt.Println("────────────────────────────────────────")
		for _, f := range rep.Findings {
			fmt.Printf("%s [%s] %s\n", ui.SeverityBadge(f.Severity, colored), f.Category, f.Title)
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

// determineExitCode maps a scan or report result to its standard CLI exit code:
// ExitSuccess (0): Completed scan with no security-policy failure established (clean / INFO only)
// ExitSecurityFail (1): Completed scan with actionable security findings (Critical, High, Medium, Low)
// ExitOperational (2): Blocked, failed, cancelled, interrupted, partial, or incomplete assessment
func determineExitCode(rep report.Report) int {
	status := rep.CompletionStatus
	if status == "" {
		status = "COMPLETED"
	}
	hasViolation := rep.Summary.CriticalCount > 0 || rep.Summary.HighCount > 0 || rep.Summary.MediumCount > 0 || rep.Summary.LowCount > 0
	cls := clierror.ClassifyAssessment(status, nil, hasViolation, nil)
	return cls.ExitCode()
}
