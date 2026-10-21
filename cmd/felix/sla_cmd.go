package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func runComplianceSLA(args []string) int {
	if len(args) == 0 {
		printSLAHelp()
		return clierror.ExitSuccess
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "policies", "policy":
		return runSLAPolicies(subArgs)
	case "list", "ls":
		return runSLAList(subArgs)
	case "view", "get", "show":
		return runSLAView(subArgs)
	case "assign":
		return runSLAAssign(subArgs)
	case "update":
		return runSLAUpdate(subArgs)
	case "accept-risk", "acceptrisk":
		return runSLAAcceptRisk(subArgs)
	case "recalculate", "recalc":
		return runSLARecalculate(subArgs)
	case "help", "--help", "-h":
		printSLAHelp()
		return clierror.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown compliance sla command: %s\n\n", sub)
		printSLAHelp()
		return clierror.ExitOperational
	}
}

func printSLAHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix compliance sla <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  policies            List configured remediation SLA policies")
	fmt.Println("  list                List tracked remediation items (supports --overdue)")
	fmt.Println("  view <id>           View detailed remediation tracking and event history")
	fmt.Println("  assign              Assign a remediation SLA to an identified finding")
	fmt.Println("  update <id>         Update lifecycle status (in_progress, remediated, reopened)")
	fmt.Println("  accept-risk <id>    Record an authorized risk acceptance")
	fmt.Println("  recalculate <id>    Explicitly recalculate an SLA deadline with audit reason")
	fmt.Println("  help                Display this help message")
	fmt.Println("\nGlobal Options for 'sla':")
	fmt.Println("  --db <path>         Custom compliance database path")
	fmt.Println("  --json              Output machine-readable JSON")
	fmt.Println("  --help, -h          Show help")
}

func openComplianceStore(dbPath string) (*compliance.SQLiteComplianceStore, error) {
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		return nil, err
	}
	// Ensure default SLA policy exists in database
	policies, err := store.ListRemediationPolicies()
	if err == nil && len(policies) == 0 {
		_ = store.SaveRemediationPolicy(compliance.DefaultRemediationSLAPolicy())
	}
	return store, nil
}

func runSLAPolicies(args []string) int {
	var dbPath string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla policies [--db <path>] [--json]")
			return clierror.ExitSuccess
		}
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	policies, err := store.ListRemediationPolicies()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed listing remediation policies: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(policies)
		return clierror.ExitSuccess
	}

	fmt.Printf("=== Configured Remediation SLA Policies (%d) ===\n", len(policies))
	for _, p := range policies {
		enabledStr := "DISABLED"
		if p.Enabled {
			enabledStr = "ENABLED"
		}
		fmt.Printf("\nPolicy ID:    %s (v%s) [%s] Priority: %d\n", p.ID, p.Version, enabledStr, p.Priority)
		if p.Description != "" {
			fmt.Printf("Description:  %s\n", p.Description)
		}
		fmt.Printf("Rules:\n")
		for sev, dur := range p.Rules {
			fmt.Printf("  * %-10s -> %s\n", sev, dur)
		}
		if p.DefaultRule != "" {
			fmt.Printf("  * %-10s -> %s\n", "DEFAULT", p.DefaultRule)
		}
	}

	return clierror.ExitSuccess
}

func runSLAList(args []string) int {
	var (
		dbPath      string
		jsonOutput  bool
		onlyOverdue bool
		severity    string
		status      string
		assessment  string
		policyID    string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--overdue":
			onlyOverdue = true
		case "--severity", "-s":
			if i+1 < len(args) {
				severity = args[i+1]
				i++
			}
		case "--status":
			if i+1 < len(args) {
				status = args[i+1]
				i++
			}
		case "--assessment", "-a":
			if i+1 < len(args) {
				assessment = args[i+1]
				i++
			}
		case "--policy":
			if i+1 < len(args) {
				policyID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla list [--overdue] [--severity <sev>] [--status <status>] [--assessment <id>] [--json]")
			return clierror.ExitSuccess
		}
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	filter := compliance.RemediationFilter{
		AssessmentID: assessment,
		Severity:     severity,
		Status:       compliance.RemediationLifecycleStatus(status),
		PolicyID:     policyID,
		OnlyOverdue:  onlyOverdue,
	}

	records, err := store.ListRemediationRecords(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed querying remediation records: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(records)
		if onlyOverdue && len(records) > 0 {
			return clierror.ExitSecurityFail
		}
		return clierror.ExitSuccess
	}

	title := "Tracked Remediation Items"
	if onlyOverdue {
		title = "OVERDUE Remediation Items"
	}
	fmt.Printf("=== %s (%d) ===\n", title, len(records))

	if len(records) == 0 {
		fmt.Println("No remediation records match the specified criteria.")
		return clierror.ExitSuccess
	}

	for _, r := range records {
		overdueTag := ""
		if r.IsOverdue {
			overdueTag = " [OVERDUE]"
		}
		fmt.Printf("\n[%s] %s (%s)%s\n", r.ID, r.FindingID, r.Severity, overdueTag)
		if r.FindingTitle != "" {
			fmt.Printf("  Title:      %s\n", r.FindingTitle)
		}
		fmt.Printf("  Status:     %s (computed SLA: %s)\n", r.Status, r.ComputedSLAStatus)
		fmt.Printf("  Deadline:   %s\n", r.Deadline.Format(time.RFC3339))
		if r.ControlID != "" {
			fmt.Printf("  Control:    %s\n", r.ControlID)
		}
		if r.IsOverdue {
			fmt.Printf("  Expired:    %s ago\n", time.Since(r.Deadline).Round(time.Minute))
		} else if r.TimeRemaining > 0 {
			fmt.Printf("  Remaining:  %s\n", r.TimeRemaining.Round(time.Minute))
		}
	}

	if onlyOverdue && len(records) > 0 {
		return clierror.ExitSecurityFail
	}
	return clierror.ExitSuccess
}

func runSLAView(args []string) int {
	var id string
	var dbPath string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla view <remediation-id> [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && id == "" {
				id = arg
			}
		}
	}

	if id == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: remediation ID must be specified")
		return clierror.ExitOperational
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	rec, err := store.GetRemediationRecord(id)
	if err != nil {
		// Also try looking up by Finding ID
		rec, err = store.GetRemediationRecordByFinding(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Remediation record %q not found: %v\n", id, err)
			return clierror.ExitOperational
		}
	}

	history, err := store.GetRemediationHistory(rec.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Warning: failed loading history events: %v\n", err)
	}

	if jsonOutput {
		out := map[string]any{
			"record":  rec,
			"history": history,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return clierror.ExitSuccess
	}

	fmt.Printf("=== Remediation Record: %s ===\n", rec.ID)
	fmt.Printf("Finding ID:     %s\n", rec.FindingID)
	if rec.FindingTitle != "" {
		fmt.Printf("Finding Title:  %s\n", rec.FindingTitle)
	}
	fmt.Printf("Severity:       %s (source: %s)\n", rec.Severity, rec.SeveritySource)
	fmt.Printf("Status:         %s\n", rec.Status)
	fmt.Printf("Computed SLA:   %s (is_overdue: %t)\n", rec.ComputedSLAStatus, rec.IsOverdue)
	fmt.Printf("SLA Policy:     %s (v%s) [%s]\n", rec.PolicyID, rec.PolicyVersion, rec.PolicyRuleMatched)
	fmt.Printf("SLA Start Time: %s\n", rec.SLAStartTime.Format(time.RFC3339))
	fmt.Printf("Deadline:       %s\n", rec.Deadline.Format(time.RFC3339))

	if rec.RiskAcceptance != nil {
		fmt.Printf("\n[Risk Acceptance Details]\n")
		fmt.Printf("  Author:       %s\n", rec.RiskAcceptance.Author)
		fmt.Printf("  Rationale:    %s\n", rec.RiskAcceptance.Rationale)
		fmt.Printf("  Accepted At:  %s\n", rec.RiskAcceptance.AcceptedAt.Format(time.RFC3339))
		if rec.RiskAcceptance.ExpiresAt != nil {
			fmt.Printf("  Expires At:   %s\n", rec.RiskAcceptance.ExpiresAt.Format(time.RFC3339))
		}
	}

	if len(history) > 0 {
		fmt.Printf("\n=== Auditable History Events (%d) ===\n", len(history))
		for i, h := range history {
			fmt.Printf("  [%d] %s: %s (Actor: %s, Reason: %s) at %s\n",
				i+1, h.EventType, h.ToStatus, h.Actor, h.Reason, h.Timestamp.Format(time.RFC3339))
		}
	}

	return clierror.ExitSuccess
}

func runSLAAssign(args []string) int {
	var (
		findingID    string
		severity     string
		policyID     string
		assessmentID string
		controlID    string
		title        string
		category     string
		source       string
		actor        string
		dbPath       string
		jsonOutput   bool
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--finding", "-f":
			if i+1 < len(args) {
				findingID = args[i+1]
				i++
			}
		case "--severity", "-s":
			if i+1 < len(args) {
				severity = args[i+1]
				i++
			}
		case "--policy", "-p":
			if i+1 < len(args) {
				policyID = args[i+1]
				i++
			}
		case "--assessment", "-a":
			if i+1 < len(args) {
				assessmentID = args[i+1]
				i++
			}
		case "--control", "-c":
			if i+1 < len(args) {
				controlID = args[i+1]
				i++
			}
		case "--title":
			if i+1 < len(args) {
				title = args[i+1]
				i++
			}
		case "--category":
			if i+1 < len(args) {
				category = args[i+1]
				i++
			}
		case "--source":
			if i+1 < len(args) {
				source = args[i+1]
				i++
			}
		case "--actor":
			if i+1 < len(args) {
				actor = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla assign --finding <id> [--severity <sev>] [--policy <id>] [--assessment <id>] [--control <id>] [--json]")
			return clierror.ExitSuccess
		}
	}

	if findingID == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --finding must be provided")
		return clierror.ExitOperational
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	// Select or load policy
	var policy *compliance.RemediationSLAPolicy
	if policyID != "" {
		p, err := store.GetRemediationPolicy(policyID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Policy %q not found: %v\n", policyID, err)
			return clierror.ExitOperational
		}
		policy = p
	} else {
		policies, err := store.ListRemediationPolicies()
		if err == nil && len(policies) > 0 {
			sel, err := compliance.SelectMatchingPolicy(policies, category, source)
			if err == nil {
				policy = sel
			}
		}
		if policy == nil {
			policy = compliance.DefaultRemediationSLAPolicy()
		}
	}

	if severity == "" {
		severity = "HIGH"
	}

	svc := compliance.NewRemediationService(compliance.RealClock{}, compliance.DefaultWarningWindow)
	rec, event, err := svc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       findingID,
		FindingSource:   source,
		FindingTitle:    title,
		FindingCategory: category,
		AssessmentID:    assessmentID,
		ControlID:       controlID,
		Severity:        severity,
		SeveritySource:  "cli_assignment",
		Policy:          policy,
		Actor:           actor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed assigning SLA: %v\n", err)
		return clierror.ExitOperational
	}

	if err := store.SaveRemediationRecord(rec, event); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed persisting remediation record: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return clierror.ExitSuccess
	}

	fmt.Printf("[+] SLA Assigned Successfully\n")
	fmt.Printf("Remediation ID: %s\n", rec.ID)
	fmt.Printf("Finding ID:     %s\n", rec.FindingID)
	fmt.Printf("Severity:       %s\n", rec.Severity)
	fmt.Printf("Policy:         %s (v%s) [%s]\n", rec.PolicyID, rec.PolicyVersion, rec.PolicyRuleMatched)
	fmt.Printf("Deadline:       %s\n", rec.Deadline.Format(time.RFC3339))
	return clierror.ExitSuccess
}

func runSLAUpdate(args []string) int {
	var (
		id         string
		status     string
		reason     string
		actor      string
		dbPath     string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--status", "-s":
			if i+1 < len(args) {
				status = args[i+1]
				i++
			}
		case "--reason", "-r":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		case "--actor":
			if i+1 < len(args) {
				actor = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla update <id> --status <in_progress|remediated|reopened> [--reason <text>] [--actor <name>] [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && id == "" {
				id = arg
			}
		}
	}

	if id == "" || status == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: remediation ID and --status must be specified")
		return clierror.ExitOperational
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	rec, err := store.GetRemediationRecord(id)
	if err != nil {
		rec, err = store.GetRemediationRecordByFinding(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Remediation record %q not found: %v\n", id, err)
			return clierror.ExitOperational
		}
	}

	svc := compliance.NewRemediationService(compliance.RealClock{}, compliance.DefaultWarningWindow)
	event, err := svc.TransitionStatus(rec, compliance.RemediationLifecycleStatus(status), actor, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid status transition: %v\n", err)
		return clierror.ExitOperational
	}

	if err := store.SaveRemediationRecord(rec, event); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed saving remediation update: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return clierror.ExitSuccess
	}

	fmt.Printf("[+] Remediation Status Updated: %s -> %s\n", event.FromStatus, event.ToStatus)
	fmt.Printf("Remediation ID: %s\n", rec.ID)
	fmt.Printf("Computed SLA:   %s\n", rec.ComputedSLAStatus)
	return clierror.ExitSuccess
}

func runSLAAcceptRisk(args []string) int {
	var (
		id         string
		rationale  string
		author     string
		dbPath     string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--rationale", "-r":
			if i+1 < len(args) {
				rationale = args[i+1]
				i++
			}
		case "--author", "-a":
			if i+1 < len(args) {
				author = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla accept-risk <id> --rationale <text> --author <name> [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && id == "" {
				id = arg
			}
		}
	}

	if id == "" || rationale == "" || author == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: remediation ID, --rationale, and --author are mandatory for risk acceptance")
		return clierror.ExitOperational
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	rec, err := store.GetRemediationRecord(id)
	if err != nil {
		rec, err = store.GetRemediationRecordByFinding(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Remediation record %q not found: %v\n", id, err)
			return clierror.ExitOperational
		}
	}

	svc := compliance.NewRemediationService(compliance.RealClock{}, compliance.DefaultWarningWindow)
	event, err := svc.AcceptRisk(rec, rationale, author, nil, author)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed accepting risk: %v\n", err)
		return clierror.ExitOperational
	}

	if err := store.SaveRemediationRecord(rec, event); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed saving risk acceptance: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return clierror.ExitSuccess
	}

	fmt.Printf("[+] Risk Acceptance Recorded Successfully\n")
	fmt.Printf("Remediation ID: %s\n", rec.ID)
	fmt.Printf("Status:         %s (NOT counted as remediated)\n", rec.Status)
	fmt.Printf("Author:         %s\n", author)
	fmt.Printf("Rationale:      %s\n", rationale)
	return clierror.ExitSuccess
}

func runSLARecalculate(args []string) int {
	var (
		id         string
		policyID   string
		reason     string
		actor      string
		dbPath     string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--reason", "-r":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		case "--policy", "-p":
			if i+1 < len(args) {
				policyID = args[i+1]
				i++
			}
		case "--actor":
			if i+1 < len(args) {
				actor = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix compliance sla recalculate <id> --reason <text> [--policy <id>] [--actor <name>] [--json]")
			return clierror.ExitSuccess
		default:
			if !strings.HasPrefix(arg, "-") && id == "" {
				id = arg
			}
		}
	}

	if id == "" || reason == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: remediation ID and --reason must be specified")
		return clierror.ExitOperational
	}

	store, err := openComplianceStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Operational error opening compliance store: %v\n", err)
		return clierror.ExitOperational
	}
	defer store.Close()

	rec, err := store.GetRemediationRecord(id)
	if err != nil {
		rec, err = store.GetRemediationRecordByFinding(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Remediation record %q not found: %v\n", id, err)
			return clierror.ExitOperational
		}
	}

	var policy *compliance.RemediationSLAPolicy
	targetPolicyID := rec.PolicyID
	if policyID != "" {
		targetPolicyID = policyID
	}
	p, err := store.GetRemediationPolicy(targetPolicyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Target policy %q not found: %v\n", targetPolicyID, err)
		return clierror.ExitOperational
	}
	policy = p

	svc := compliance.NewRemediationService(compliance.RealClock{}, compliance.DefaultWarningWindow)
	event, err := svc.RecalculateDeadline(rec, policy, reason, actor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed recalculating deadline: %v\n", err)
		return clierror.ExitOperational
	}

	if err := store.SaveRemediationRecord(rec, event); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed saving recalculation: %v\n", err)
		return clierror.ExitOperational
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return clierror.ExitSuccess
	}

	fmt.Printf("[+] SLA Deadline Recalculated Successfully\n")
	fmt.Printf("Remediation ID: %s\n", rec.ID)
	fmt.Printf("New Deadline:   %s\n", rec.Deadline.Format(time.RFC3339))
	fmt.Printf("Reason:         %s\n", reason)
	return clierror.ExitSuccess
}
