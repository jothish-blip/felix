package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/assessment"
	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/businesslogic"
	"felix/pkg/cloudsec"
	"felix/pkg/correlation"
	"felix/pkg/report"
	"felix/pkg/sessionsec"
	"felix/pkg/webvuln"
	"github.com/google/uuid"
)

func runAssessment(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printAssessmentHelp()
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "create":
		return runAssessmentCreate(subArgs)
	case "list":
		return runAssessmentList(subArgs)
	case "show":
		return runAssessmentShow(subArgs)
	case "target":
		if len(subArgs) > 0 && subArgs[0] == "add" {
			return runAssessmentTargetAdd(subArgs[1:])
		}
		return runAssessmentTargetAdd(subArgs)
	case "scope":
		if len(subArgs) > 0 && subArgs[0] == "add" {
			return runAssessmentScopeAdd(subArgs[1:])
		}
		return runAssessmentScopeAdd(subArgs)
	case "exclude":
		if len(subArgs) > 0 && subArgs[0] == "add" {
			return runAssessmentExcludeAdd(subArgs[1:])
		}
		return runAssessmentExcludeAdd(subArgs)
	case "authorize":
		return runAssessmentAuthorize(subArgs)
	case "run":
		return runAssessmentRun(subArgs)
	case "findings":
		return runAssessmentFindings(subArgs)
	case "inventory":
		return runAssessmentInventory(subArgs)
	case "auth":
		return runAssessmentAuth(subArgs)
	case "authz":
		return runAssessmentAuthz(subArgs)
	case "apisec", "api":
		return runAssessmentAPISec(subArgs)
	case "webvuln", "vuln":
		return runAssessmentWebVuln(subArgs)
	case "sessionsec", "session", "identity":
		return runAssessmentSessionSec(subArgs)
	case "cloudsec", "cloud":
		return runAssessmentCloudSec(subArgs)
	case "businesslogic", "bizlogic", "logic":
		return runAssessmentBusinessLogic(subArgs)
	case "correlate", "correlation", "attackpaths", "paths":
		return runAssessmentCorrelate(subArgs)
	case "reports":
		return runAssessmentReports(subArgs)
	case "cancel":
		return runAssessmentCancel(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown assessment subcommand: %s\n\n", sub)
		printAssessmentHelp()
		return 2
	}
}

func printAssessmentHelp() {
	fmt.Println("Usage: felix assessment <subcommand> [flags]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  create       Create a new security assessment project")
	fmt.Println("  list         List security assessments")
	fmt.Println("  show         Display comprehensive assessment dossier")
	fmt.Println("  target add   Add target URL to assessment")
	fmt.Println("  scope add    Add scope rule to assessment")
	fmt.Println("  exclude add  Add exclusion rule (hostname, path, URL)")
	fmt.Println("  authorize    Record client authorization and approve assessment")
	fmt.Println("  run          Execute authorized assessment against approved targets")
	fmt.Println("  findings     Inspect findings recorded for an assessment")
	fmt.Println("  inventory    Inspect discovered attack-surface assets and relationships")
	fmt.Println("  auth         Inspect discovered authentication surfaces, cookies, tokens, and protection")
	fmt.Println("  authz        Test and inspect API authorization, BOLA/IDOR, BFLA, BOPLA, and privilege escalation")
	fmt.Println("  apisec       Assess OWASP API Security Top 10 (2023) categories and API inventory")
	fmt.Println("  webvuln      Assess and verify web application vulnerabilities (XSS, SQLi, SSTI, SSRF, etc.)")
	fmt.Println("  sessionsec   Assess session lifecycle, token handling, and identity boundaries (WSTG-SESS/ATHN)")
	fmt.Println("  cloudsec     Assess cloud security across AWS, Azure, and GCP (External & Credentialed Modes)")
	fmt.Println("  businesslogic Assess business logic workflows, state transitions, replay, and invariants")
	fmt.Println("  correlate    Correlate findings into evidence-backed attack paths and combined risk")
	fmt.Println("  reports      List generated report files for an assessment")
	fmt.Println("  cancel       Cancel an active or pending assessment")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment create --client \"Acme Corp\" --name \"Q1 Web Audit\" --target https://example.com")
	fmt.Println("  felix assessment authorize <asm-ref> --authorizer \"Jane Doe\" --role \"CISO\" --reference \"AUTH-001\" --valid-days 30")
	fmt.Println("  felix assessment run <asm-ref> --concurrency 5")
	fmt.Println("  felix assessment findings <asm-ref>")
	fmt.Println("  felix assessment inventory <asm-ref>")
	fmt.Println("  felix assessment auth <asm-ref> --verbose")
	fmt.Println("  felix assessment authz <asm-ref> --policy policy.json --run")
	fmt.Println("  felix assessment apisec <asm-ref> --run --spec openapi.json")
	fmt.Println("  felix assessment webvuln <asm-ref> --run")
	fmt.Println("  felix assessment sessionsec <asm-ref> --run")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode external")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode credentialed --provider aws --credentials aws_creds.json --run")
	fmt.Println("  felix assessment businesslogic <asm-ref> --run")
	fmt.Println("  felix assessment correlate <asm-ref> --run")
	fmt.Println("  felix assessment correlate <asm-ref> --status VERIFIED --verbose")
	fmt.Println("  felix assessment reports <asm-ref>")
}

func runAssessmentCreate(args []string) int {
	var (
		clientRef  string
		name       string
		notes      string
		scopeMode  string
		targets    []string
		scopeRules []string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--client", "-c":
			if i+1 < len(args) {
				clientRef = args[i+1]
				i++
			}
		case "--name", "-n":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--notes", "--desc", "--description":
			if i+1 < len(args) {
				notes = args[i+1]
				i++
			}
		case "--scope-mode":
			if i+1 < len(args) {
				scopeMode = args[i+1]
				i++
			}
		case "--target", "-t":
			if i+1 < len(args) {
				targets = append(targets, args[i+1])
				i++
			}
		case "--scope-rule":
			if i+1 < len(args) {
				scopeRules = append(scopeRules, args[i+1])
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printAssessmentHelp()
			return 0
		}
	}

	clientRef = strings.TrimSpace(clientRef)
	if clientRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --client is required. Specify client ID or Name.\n")
		return 2
	}
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --name is required for assessment.\n")
		return 2
	}

	if scopeMode == "" {
		scopeMode = "same-origin"
	}
	switch scopeMode {
	case "same-origin", "subdomains", "explicit":
	default:
		fmt.Fprintf(os.Stderr, "[-] Error: invalid --scope-mode %q (allowed: same-origin, subdomains, explicit)\n", scopeMode)
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	// Verify client exists
	client, err := store.GetClient(clientRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Client %q not found: %v\n", clientRef, err)
		return 1
	}

	// Validate target URLs upfront
	for _, t := range targets {
		if _, err := assessment.ValidateTargetURL(t); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Target URL validation error: %v\n", err)
			return 2
		}
	}

	asmID := uuid.New().String()
	asmRef := assessment.GenerateAssessmentRef()
	now := time.Now().UTC()

	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            asmRef,
		ClientID:       client.ID,
		Name:           name,
		Description:    notes,
		AssessmentType: "WEB_SECURITY",
		Status:         assessment.StatusDraft,
		CreatedAt:      now,
		UpdatedAt:      now,
		ScopeMode:      scopeMode,
	}

	if err := store.CreateAssessment(asm); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create assessment: %v\n", err)
		return 1
	}

	// Add targets
	for _, tURL := range targets {
		normURL, _ := assessment.NormalizeTargetURL(tURL)
		tRecord := &assessment.AssessmentTarget{
			ID:           uuid.New().String(),
			AssessmentID: asmID,
			TargetURL:    normURL,
			TargetType:   assessment.TargetWebsite,
			ScopeStatus:  "APPROVED",
			CreatedAt:    now,
		}
		if err := store.AddTarget(tRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: Failed to add target %s: %v\n", tURL, err)
		}
	}

	// Add scope rules
	for _, sr := range scopeRules {
		parts := strings.SplitN(sr, ":", 2)
		rType := "subdomains"
		rPattern := sr
		if len(parts) == 2 {
			rType = parts[0]
			rPattern = parts[1]
		}
		ruleRecord := &assessment.ScopeRule{
			ID:           uuid.New().String(),
			AssessmentID: asmID,
			RuleType:     rType,
			Pattern:      rPattern,
			CreatedAt:    now,
		}
		if err := store.AddScopeRule(ruleRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: Failed to add scope rule %s: %v\n", sr, err)
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(asm)
		return 0
	}

	fmt.Printf("[+] Assessment created successfully\n")
	fmt.Printf("    Reference:  %s\n", asm.Ref)
	fmt.Printf("    ID:         %s\n", asm.ID)
	fmt.Printf("    Client:     %s (%s)\n", client.Name, client.ID)
	fmt.Printf("    Name:       %s\n", asm.Name)
	fmt.Printf("    Status:     %s\n", asm.Status)
	fmt.Printf("    Scope Mode: %s\n", asm.ScopeMode)
	fmt.Printf("    Targets:    %d configured\n", len(targets))
	fmt.Printf("\nNext step: record authorization before execution:\n")
	fmt.Printf("  felix assessment authorize %s --authorizer <name> --role <role> --reference <doc-ref>\n", asm.Ref)
	return 0
}

func runAssessmentList(args []string) int {
	var (
		clientRef  string
		statusFil  string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--client", "-c":
			if i+1 < len(args) {
				clientRef = args[i+1]
				i++
			}
		case "--status", "-s":
			if i+1 < len(args) {
				statusFil = strings.ToUpper(args[i+1])
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printAssessmentHelp()
			return 0
		}
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	assessments, err := store.ListAssessments(clientRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to list assessments: %v\n", err)
		return 1
	}

	if statusFil != "" {
		var filtered []assessment.Assessment
		for _, a := range assessments {
			if string(a.Status) == statusFil {
				filtered = append(filtered, a)
			}
		}
		assessments = filtered
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if assessments == nil {
			assessments = []assessment.Assessment{}
		}
		_ = enc.Encode(assessments)
		return 0
	}

	if len(assessments) == 0 {
		fmt.Println("No assessments found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "REF\tNAME\tSTATUS\tMODE\tFINDINGS\tCREATED")
	for _, a := range assessments {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			a.Ref, a.Name, a.Status, a.ScopeMode, a.FindingCount, a.CreatedAt.Format("2006-01-02 15:04"))
	}
	_ = w.Flush()
	return 0
}

func runAssessmentShow(args []string) int {
	var (
		assessmentRef string
		jsonOutput    bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printAssessmentHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref required. Usage: felix assessment show <asm-ref>\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	client, _ := store.GetClient(asm.ClientID)
	targets, _ := store.GetTargets(asm.ID)
	scopeRules, _ := store.GetScopeRules(asm.ID)
	exclusions, _ := store.GetExclusions(asm.ID)
	auth, _ := store.GetAuthorization(asm.ID)
	executions, _ := store.ListExecutions(asm.ID)
	reports, _ := store.GetReports(asm.ID)

	if jsonOutput {
		out := map[string]any{
			"assessment":  asm,
			"client":      client,
			"targets":     targets,
			"scope_rules": scopeRules,
			"exclusions":  exclusions,
			"auth":        auth,
			"executions":  executions,
			"reports":     reports,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	clientName := asm.ClientID
	if client != nil {
		clientName = fmt.Sprintf("%s (%s)", client.Name, client.ID)
	}

	fmt.Printf("===========================================================\n")
	fmt.Printf("ASSESSMENT DOSSIER: %s\n", asm.Ref)
	fmt.Printf("===========================================================\n")
	fmt.Printf("  ID:           %s\n", asm.ID)
	fmt.Printf("  Name:         %s\n", asm.Name)
	fmt.Printf("  Client:       %s\n", clientName)
	fmt.Printf("  Status:       %s\n", asm.Status)
	fmt.Printf("  Scope Mode:   %s\n", asm.ScopeMode)
	if asm.Description != "" {
		fmt.Printf("  Notes:        %s\n", asm.Description)
	}
	fmt.Printf("  Created:      %s\n", asm.CreatedAt.Format(time.RFC3339))
	if asm.StartedAt != nil {
		fmt.Printf("  Started:      %s\n", asm.StartedAt.Format(time.RFC3339))
	}
	if asm.CompletedAt != nil {
		fmt.Printf("  Completed:    %s\n", asm.CompletedAt.Format(time.RFC3339))
	}

	// Authorization
	fmt.Printf("\nAuthorization:\n")
	if auth == nil {
		fmt.Printf("  [!] Status: PENDING (Assessment not yet authorized)\n")
	} else {
		valid, reason := auth.IsCurrentlyValid(time.Now().UTC())
		validStr := "[+] VALID"
		if !valid {
			validStr = fmt.Sprintf("[-] INVALID: %s", reason)
		}
		fmt.Printf("  Status:       %s (%s)\n", auth.Status, validStr)
		fmt.Printf("  Authorizer:   %s\n", auth.AuthorizingParty)
		if auth.AuthorizationMethod != "" {
			fmt.Printf("  Role/Method:  %s\n", auth.AuthorizationMethod)
		}
		if auth.ScopeDocRef != "" {
			fmt.Printf("  Reference:    %s\n", auth.ScopeDocRef)
		}
		if auth.ValidFrom != nil {
			fmt.Printf("  Valid From:   %s\n", auth.ValidFrom.Format(time.RFC3339))
		}
		if auth.ValidUntil != nil {
			fmt.Printf("  Valid Until:  %s\n", auth.ValidUntil.Format(time.RFC3339))
		}
	}

	// Targets
	fmt.Printf("\nTargets (%d):\n", len(targets))
	if len(targets) == 0 {
		fmt.Println("  (Zero targets configured)")
	} else {
		for _, t := range targets {
			fmt.Printf("  - [%s] %s\n", t.ScopeStatus, t.TargetURL)
		}
	}

	// Scope Rules
	if len(scopeRules) > 0 {
		fmt.Printf("\nScope Rules (%d):\n", len(scopeRules))
		for _, r := range scopeRules {
			fmt.Printf("  - %s: %s\n", r.RuleType, r.Pattern)
		}
	}

	// Exclusions
	if len(exclusions) > 0 {
		fmt.Printf("\nExclusions (%d):\n", len(exclusions))
		for _, e := range exclusions {
			reason := ""
			if e.Reason != "" {
				reason = fmt.Sprintf(" (%s)", e.Reason)
			}
			fmt.Printf("  - [%s] %s%s\n", e.ExclusionType, e.Pattern, reason)
		}
	}

	// Executions
	if len(executions) > 0 {
		fmt.Printf("\nExecution Runs (%d):\n", len(executions))
		for _, ex := range executions {
			fmt.Printf("  - Run %s: %s | Started: %s | Duration: %d ms | Requests: %d\n",
				ex.ID[:8], ex.Status, ex.StartedAt.Format("2006-01-02 15:04:05"), ex.DurationMs, ex.RequestCount)
		}
	}

	// Reports
	if len(reports) > 0 {
		fmt.Printf("\nGenerated Reports (%d):\n", len(reports))
		for _, rep := range reports {
			fmt.Printf("  - [%s] %s (%s)\n", rep.Format, rep.FilePath, rep.CreatedAt.Format("2006-01-02 15:04"))
		}
	}

	return 0
}

func runAssessmentTargetAdd(args []string) int {
	var (
		assessmentRef string
		targetURL     string
		targetType    string
		label         string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--url", "-u":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		case "--type":
			if i+1 < len(args) {
				targetType = args[i+1]
				i++
			}
		case "--label", "--notes":
			if i+1 < len(args) {
				label = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment target add <assessment-id> --url <url> [--notes \"...\"]")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}
	if targetURL == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --url is required\n")
		return 2
	}

	if _, err := assessment.ValidateTargetURL(targetURL); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Target URL validation error: %v\n", err)
		return 2
	}

	normURL, _ := assessment.NormalizeTargetURL(targetURL)

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	if targetType == "" {
		targetType = string(assessment.TargetWebsite)
	}

	t := &assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    normURL,
		TargetType:   assessment.TargetType(targetType),
		ScopeStatus:  "APPROVED",
		Label:        label,
		CreatedAt:    time.Now().UTC(),
	}

	if err := store.AddTarget(t); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to add target: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Added approved target %s to assessment %s\n", normURL, asm.Ref)
	return 0
}

func runAssessmentScopeAdd(args []string) int {
	var (
		assessmentRef string
		rule          string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--rule", "-r":
			if i+1 < len(args) {
				rule = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment scope add <assessment-id> --rule \"subdomains:example.com\"")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}
	if rule == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --rule is required\n")
		return 2
	}

	parts := strings.SplitN(rule, ":", 2)
	rType := "subdomains"
	rPattern := rule
	if len(parts) == 2 {
		rType = parts[0]
		rPattern = parts[1]
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	sr := &assessment.ScopeRule{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		RuleType:     rType,
		Pattern:      rPattern,
		CreatedAt:    time.Now().UTC(),
	}

	if err := store.AddScopeRule(sr); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to add scope rule: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Added scope rule (%s: %s) to assessment %s\n", rType, rPattern, asm.Ref)
	return 0
}

func runAssessmentExcludeAdd(args []string) int {
	var (
		assessmentRef string
		exType        string
		pattern       string
		reason        string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--type", "-t":
			if i+1 < len(args) {
				exType = strings.ToUpper(args[i+1])
				i++
			}
		case "--pattern", "-p":
			if i+1 < len(args) {
				pattern = args[i+1]
				i++
			}
		case "--reason", "-r":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment exclude add <assessment-id> --type <HOSTNAME|PATH_PREFIX|EXACT_URL> --pattern <pattern> [--reason \"...\"]")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}
	if pattern == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --pattern is required\n")
		return 2
	}

	switch exType {
	case assessment.ExclusionHostname, assessment.ExclusionPathPrefix, assessment.ExclusionExactURL:
	default:
		fmt.Fprintf(os.Stderr, "[-] Error: invalid --type %q (allowed: HOSTNAME, PATH_PREFIX, EXACT_URL)\n", exType)
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	ex := &assessment.Exclusion{
		ID:            uuid.New().String(),
		AssessmentID:  asm.ID,
		ExclusionType: exType,
		Pattern:       pattern,
		Reason:        reason,
		CreatedAt:     time.Now().UTC(),
	}

	if err := store.AddExclusion(ex); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to add exclusion: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Added exclusion [%s: %s] to assessment %s\n", exType, pattern, asm.Ref)
	return 0
}

func runAssessmentAuthorize(args []string) int {
	var (
		assessmentRef string
		authorizer    string
		role          string
		reference     string
		validDays     int
		validUntilStr string
		validFromStr  string
		notes         string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--authorizer", "-a":
			if i+1 < len(args) {
				authorizer = args[i+1]
				i++
			}
		case "--role", "-r":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--reference", "--ref-doc":
			if i+1 < len(args) {
				reference = args[i+1]
				i++
			}
		case "--valid-days":
			if i+1 < len(args) {
				validDays, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--valid-until":
			if i+1 < len(args) {
				validUntilStr = args[i+1]
				i++
			}
		case "--valid-from":
			if i+1 < len(args) {
				validFromStr = args[i+1]
				i++
			}
		case "--notes":
			if i+1 < len(args) {
				notes = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment authorize <assessment-id> --authorizer \"Jane Doe\" --role \"CISO\" --reference \"SEC-AUTH-001\" [--valid-days 30]")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}
	authorizer = strings.TrimSpace(authorizer)
	if authorizer == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --authorizer is required\n")
		return 2
	}

	now := time.Now().UTC()
	var validFrom *time.Time
	var validUntil *time.Time

	if validFromStr != "" {
		t, err := time.Parse(time.RFC3339, validFromStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid --valid-from timestamp format (must be RFC3339): %v\n", err)
			return 2
		}
		validFrom = &t
	}

	if validUntilStr != "" {
		t, err := time.Parse(time.RFC3339, validUntilStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid --valid-until timestamp format (must be RFC3339): %v\n", err)
			return 2
		}
		validUntil = &t
	} else if validDays > 0 {
		t := now.Add(time.Duration(validDays) * 24 * time.Hour)
		validUntil = &t
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	auth := &assessment.AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asm.ID,
		AuthorizingParty:    authorizer,
		AuthorizationMethod: role,
		DateReceived:        now,
		ValidFrom:           validFrom,
		ValidUntil:          validUntil,
		ScopeDocRef:         reference,
		InternalNotes:       notes,
		Status:              assessment.AuthApproved,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := store.SetAuthorization(auth); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to set authorization: %v\n", err)
		return 1
	}

	// Transition assessment state from DRAFT to READY
	if asm.Status == assessment.StatusDraft {
		if err := store.UpdateAssessmentStatus(asm.ID, assessment.StatusReady); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: Failed to transition assessment status to READY: %v\n", err)
		} else {
			asm.Status = assessment.StatusReady
		}
	}

	fmt.Printf("[+] Authorization recorded successfully\n")
	fmt.Printf("    Assessment:   %s (%s)\n", asm.Ref, asm.Name)
	fmt.Printf("    Authorizer:   %s\n", auth.AuthorizingParty)
	if auth.AuthorizationMethod != "" {
		fmt.Printf("    Role:         %s\n", auth.AuthorizationMethod)
	}
	if auth.ScopeDocRef != "" {
		fmt.Printf("    Reference:    %s\n", auth.ScopeDocRef)
	}
	if auth.ValidUntil != nil {
		fmt.Printf("    Valid Until:  %s\n", auth.ValidUntil.Format(time.RFC3339))
	}
	fmt.Printf("    Status:       APPROVED (Assessment is now READY for execution)\n")
	return 0
}

func runAssessmentRun(args []string) int {
	var (
		assessmentRef  string
		concurrency    int
		timeoutStr     string
		maxAssets      int
		maxSizeMB      int
		quiet          bool
		verbose        bool
		exportHTMLPath string
		exportJSONPath string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--concurrency", "-c":
			if i+1 < len(args) {
				concurrency, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--timeout", "-t":
			if i+1 < len(args) {
				timeoutStr = args[i+1]
				i++
			}
		case "--max-assets":
			if i+1 < len(args) {
				maxAssets, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--max-response-size", "--max-size":
			if i+1 < len(args) {
				maxSizeMB, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--quiet", "-q":
			quiet = true
		case "--verbose", "-v":
			verbose = true
		case "--html":
			if i+1 < len(args) {
				exportHTMLPath = args[i+1]
				i++
			}
		case "--json":
			if i+1 < len(args) {
				exportJSONPath = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment run <assessment-id> [flags]")
			fmt.Println("\nFlags:")
			fmt.Println("  --concurrency <n>        Concurrent worker threads (default: 5)")
			fmt.Println("  --timeout <duration>     Per-request HTTP timeout, e.g. 15s (default: 30s)")
			fmt.Println("  --max-assets <n>         Maximum assets to discover per target (default: 200)")
			fmt.Println("  --max-response-size <mb> Maximum response body size in MB (default: 5)")
			fmt.Println("  --html <path>            Custom destination path for assessment HTML report")
			fmt.Println("  --json <path>            Custom destination path for assessment JSON report")
			fmt.Println("  --quiet, -q              Suppress live progress output")
			fmt.Println("  --verbose, -v            Enable verbose execution logs")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	// Check interrupted runs first
	if recovered, err := store.DetectAndRecoverInterruptedRuns(); err == nil && recovered > 0 {
		if !quiet {
			fmt.Printf("[!] Recovered %d previously interrupted assessment run(s)\n", recovered)
		}
	}

	// Verify assessment exists
	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	// Setup context with interrupt handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !quiet {
			fmt.Printf("\n[!] Interrupt signal received. Gracefully finishing current tasks and saving partial findings...\n")
		}
		cancel()
	}()

	var timeoutDur time.Duration
	if timeoutStr != "" {
		t, err := time.ParseDuration(timeoutStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid --timeout duration %q: %v\n", timeoutStr, err)
			return 2
		}
		timeoutDur = t
	}

	controller := assessment.NewController(store)

	var maxSizeBytes int64
	if maxSizeMB > 0 {
		maxSizeBytes = int64(maxSizeMB) * 1024 * 1024
	}

	opts := assessment.ExecutionOptions{
		TimeoutDuration: timeoutDur,
		Concurrency:     concurrency,
		MaxAssets:       maxAssets,
		MaxSizeBytes:    maxSizeBytes,
		FelixVersion:    Version,
		BuildID:         GitCommit,
		ExportHTMLPath:  exportHTMLPath,
		ExportJSONPath:  exportJSONPath,
		Verbose:         verbose,
		ProgressFunc: func(msg string) {
			if !quiet {
				fmt.Println(msg)
			}
		},
	}

	if !quiet {
		fmt.Printf("===========================================================\n")
		fmt.Printf("  EXECUTING ASSESSMENT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("===========================================================\n")
	}

	res, err := controller.RunAssessment(ctx, asm.ID, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[-] Assessment execution failed / refused:\n    %v\n", err)
		return 1
	}

	if !quiet {
		fmt.Printf("\n===========================================================\n")
		fmt.Printf("  ASSESSMENT RUN COMPLETE: %s\n", res.Execution.ID)
		fmt.Printf("===========================================================\n")
		fmt.Printf("  Status:          %s\n", res.Execution.Status)
		if res.Execution.DurationMs > 0 {
			fmt.Printf("  Duration:        %d ms\n", res.Execution.DurationMs)
		}
		fmt.Printf("  Requests:        %d audited\n", res.Execution.RequestCount)
		totalFindings := 0
		if res.Report != nil {
			totalFindings = len(res.Report.Findings)
		}
		fmt.Printf("  Findings:        %d total\n", totalFindings)
		if res.Report != nil {
			fmt.Printf("    Critical:      %d\n", res.Report.Summary.CriticalCount)
			fmt.Printf("    High:          %d\n", res.Report.Summary.HighCount)
			fmt.Printf("    Medium:        %d\n", res.Report.Summary.MediumCount)
			fmt.Printf("    Low:           %d\n", res.Report.Summary.LowCount)
			fmt.Printf("    Info:          %d\n", res.Report.Summary.InfoCount)
		}
		if res.HTMLPath != "" {
			fmt.Printf("  HTML Report:     %s\n", res.HTMLPath)
		}
		if res.JSONPath != "" {
			fmt.Printf("  JSON Report:     %s\n", res.JSONPath)
		}
		fmt.Println()
	}

	return 0
}

func runAssessmentFindings(args []string) int {
	var (
		assessmentRef string
		severityFil   string
		verFil        string
		execIDFil     string
		jsonOutput    bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--severity", "-s":
			if i+1 < len(args) {
				severityFil = strings.ToUpper(args[i+1])
				i++
			}
		case "--verification", "-v":
			if i+1 < len(args) {
				verFil = strings.ToUpper(args[i+1])
				i++
			}
		case "--execution", "-e":
			if i+1 < len(args) {
				execIDFil = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix assessment findings <assessment-id> [--severity HIGH] [--verification VERIFIED] [--json]")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	findings, err := store.GetFindings(asm.ID, execIDFil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch findings: %v\n", err)
		return 1
	}

	// Filter findings
	var filtered []assessment.AssessmentFinding
	for _, f := range findings {
		if severityFil != "" && strings.ToUpper(f.Severity) != severityFil {
			continue
		}
		if verFil != "" && strings.ToUpper(string(f.VerificationStatus)) != verFil {
			continue
		}
		filtered = append(filtered, f)
	}
	findings = filtered

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if findings == nil {
			findings = []assessment.AssessmentFinding{}
		}
		_ = enc.Encode(findings)
		return 0
	}

	if len(findings) == 0 {
		fmt.Printf("No findings recorded for assessment %s matching criteria.\n", asm.Ref)
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tSTATUS\tSCORE\tTITLE\tTARGET")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			f.Severity, f.VerificationStatus, f.Score, f.Title, f.TargetURL)
	}
	_ = w.Flush()
	return 0
}

func runAssessmentReports(args []string) int {
	var (
		assessmentRef string
		jsonOutput    bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix assessment reports <assessment-id> [--json]")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	reports, err := store.GetReports(asm.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch reports: %v\n", err)
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if reports == nil {
			reports = []assessment.ReportRecord{}
		}
		_ = enc.Encode(reports)
		return 0
	}

	if len(reports) == 0 {
		fmt.Printf("No reports generated yet for assessment %s.\n", asm.Ref)
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "FORMAT\tPATH\tVERSION\tCREATED")
	for _, r := range reports {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			r.Format, r.FilePath, r.FelixVersion, r.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()
	return 0
}

func runAssessmentCancel(args []string) int {
	var assessmentRef string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("Usage: felix assessment cancel <assessment-id>")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	if err := store.UpdateAssessmentStatus(asm.ID, assessment.StatusCancelled); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to cancel assessment: %v\n", err)
		return 1
	}

	fmt.Printf("[+] Assessment %s marked as CANCELLED\n", asm.Ref)
	return 0
}

func runAssessmentInventory(args []string) int {
	var (
		assessmentRef string
		assetTypeFil  string
		inScopeOnly   bool
		jsonOutput    bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--type", "-t":
			if i+1 < len(args) {
				assetTypeFil = strings.ToUpper(args[i+1])
				i++
			}
		case "--in-scope":
			inScopeOnly = true
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			fmt.Println("Usage: felix assessment inventory <assessment-id> [flags]")
			fmt.Println("\nFlags:")
			fmt.Println("  --type, -t <string>  Filter by asset type (DOMAIN, SUBDOMAIN, APPLICATION, API_SERVICE, ENDPOINT, FORM, PARAMETER, AUTH_SURFACE, CLOUD_SERVICE, TECHNOLOGY)")
			fmt.Println("  --in-scope           Display in-scope assets only")
			fmt.Println("  --json               Output attack-surface inventory as JSON")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	assets, relations, err := store.GetInventory(asm.ID, "", assetTypeFil, inScopeOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch inventory: %v\n", err)
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		output := map[string]any{
			"assessment_ref": asm.Ref,
			"assessment_id":  asm.ID,
			"assets":         assets,
			"relations":      relations,
		}
		_ = enc.Encode(output)
		return 0
	}

	summary, _ := store.GetInventorySummary(asm.ID, "")
	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: ATTACK-SURFACE INVENTORY: %s\n", asm.Ref)
	fmt.Printf("  Assessment Name: %s | Client ID: %s\n", asm.Name, asm.ClientID)
	fmt.Println("===========================================================")
	if summary != nil {
		fmt.Printf("  Total Assets:        %d (%d in-scope, %d out-of-scope)\n", summary.TotalAssets, summary.InScopeAssets, summary.OutOfScopeAssets)
		fmt.Printf("  Total Relations:     %d\n", summary.TotalRelations)
		fmt.Printf("  Domains / Hosts:     %d / %d\n", summary.DomainsCount, summary.SubdomainsCount)
		fmt.Printf("  Web Services:        %d\n", summary.WebServicesCount)
		fmt.Printf("  Applications:        %d\n", summary.ApplicationsCount)
		fmt.Printf("  API Services:        %d\n", summary.APIServicesCount)
		fmt.Printf("  Endpoints:           %d\n", summary.EndpointsCount)
		fmt.Printf("  Forms / Inputs:      %d / %d\n", summary.FormsCount, summary.ParametersCount)
		fmt.Printf("  Auth Surfaces:       %d\n", summary.AuthSurfacesCount)
		fmt.Printf("  Cloud Services:      %d\n", summary.CloudServicesCount)
		fmt.Printf("  Technologies:        %d\n", summary.TechnologiesCount)
		fmt.Println("-----------------------------------------------------------")
	}

	if len(assets) == 0 {
		fmt.Println("No attack-surface assets recorded for this assessment yet.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tSTATUS\tCONFIDENCE\tIDENTIFIER\tDISCOVERY METHOD")
	for _, a := range assets {
		scopeTag := ""
		if !a.InScope {
			scopeTag = " [OUT_OF_SCOPE]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s%s\t%s\n",
			a.Type, a.DiscoveryStatus, a.Confidence, a.CanonicalID, scopeTag, a.DiscoveryMethod)
	}
	_ = w.Flush()
	return 0
}

func runAssessmentAuth(args []string) int {
	var (
		assessmentRef  string
		categoryFilter string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--assessment", "--id", "--ref":
			if i+1 < len(args) {
				assessmentRef = args[i+1]
				i++
			}
		case "--category", "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case "--json":
			jsonOutput = true
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h":
			fmt.Println("Usage: felix assessment auth <assessment-ref> [flags]")
			fmt.Println("\nFlags:")
			fmt.Println("  --category, -c <string>  Filter by category (LOGIN, REGISTRATION, PASSWORD_RESET, MFA, SESSION, OAUTH_SSO, ALTERNATIVE, PROTECTED_ENDPOINT)")
			fmt.Println("  --json                   Output authentication intelligence as JSON")
			fmt.Println("  --verbose, -v            Display extended evidence details and auth state")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	var authInv *auth.AuthInventory
	authInv, err = store.GetAuthInventory(asm.ID, "", categoryFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch auth inventory: %v\n", err)
		return 1
	}

	authSummary, _ := store.GetAuthSummary(asm.ID, "")

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		output := map[string]any{
			"assessment_ref":      asm.Ref,
			"assessment_id":       asm.ID,
			"summary":             authSummary,
			"surfaces":            authInv.Surfaces,
			"cookies":             authInv.Cookies,
			"tokens":              authInv.Tokens,
			"protected_endpoints": authInv.ProtectedEndpoints,
		}
		_ = enc.Encode(output)
		return 0
	}

	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: AUTHENTICATION INTELLIGENCE: %s\n", asm.Ref)
	fmt.Printf("  Assessment Name: %s | Client ID: %s\n", asm.Name, asm.ClientID)
	fmt.Println("===========================================================")
	if authSummary != nil {
		fmt.Printf("  Total Surfaces:         %d\n", authSummary.TotalSurfaces)
		fmt.Printf("  Session / Insecure Ck:  %d / %d\n", authSummary.SessionCookies, authSummary.InsecureCookies)
		fmt.Printf("  Token Artifacts:        %d\n", authSummary.TotalTokens)
		fmt.Printf("  Protected Endpoints:    %d\n", authSummary.ProtectedEndpoints)
		if len(authSummary.SurfacesByCategory) > 0 {
			fmt.Print("  Category Breakdown:     ")
			var catParts []string
			for k, v := range authSummary.SurfacesByCategory {
				catParts = append(catParts, fmt.Sprintf("%s=%d", k, v))
			}
			fmt.Println(strings.Join(catParts, ", "))
		}
		fmt.Println("-----------------------------------------------------------")
	}

	// 1. Surfaces Table
	if len(authInv.Surfaces) > 0 {
		fmt.Printf("\n[+] AUTHENTICATION SURFACES (%d)\n", len(authInv.Surfaces))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CATEGORY\tSUBTYPE\tCONFIDENCE\tSTATE\tIDENTIFIER\tDISCOVERY METHOD\tEXPLANATION")
			for _, s := range authInv.Surfaces {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.Category, s.Subtype, s.Confidence, s.AuthState, s.Identifier, s.DiscoveryMethod, s.Explanation)
			}
		} else {
			fmt.Fprintln(w, "CATEGORY\tSUBTYPE\tCONFIDENCE\tIDENTIFIER\tDISCOVERY METHOD")
			for _, s := range authInv.Surfaces {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					s.Category, s.Subtype, s.Confidence, s.Identifier, s.DiscoveryMethod)
			}
		}
		_ = w.Flush()
	} else {
		fmt.Println("\nNo authentication surfaces discovered matching criteria.")
	}

	// 2. Cookies Table
	if len(authInv.Cookies) > 0 {
		fmt.Printf("\n[+] COOKIE SECURITY ANALYSIS (%d)\n", len(authInv.Cookies))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "COOKIE NAME\tPURPOSE\tSECURE\tHTTPONLY\tSAMESITE\tDEFECTS")
		for _, c := range authInv.Cookies {
			defects := "-"
			if len(c.SecurityDefects) > 0 {
				defects = strings.Join(c.SecurityDefects, "; ")
			}
			fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%s\t%s\n",
				c.Name, c.Purpose, c.IsSecure, c.IsHTTPOnly, c.SameSite, defects)
		}
		_ = w.Flush()
	}

	// 3. Tokens Table
	if len(authInv.Tokens) > 0 {
		fmt.Printf("\n[+] TOKEN ARTIFACTS (%d)\n", len(authInv.Tokens))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tSUBTYPE\tNAME\tLOCATION\tALGORITHM")
		for _, t := range authInv.Tokens {
			alg := t.Algorithm
			if alg == "" {
				alg = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				t.TokenType, t.Subtype, t.Name, t.Location, alg)
		}
		_ = w.Flush()
	}

	// 4. Protected Endpoints Table
	if len(authInv.ProtectedEndpoints) > 0 {
		fmt.Printf("\n[+] PROTECTED ENDPOINTS (%d)\n", len(authInv.ProtectedEndpoints))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "METHOD\tENDPOINT\tSTATUS\tPROTECTION\tAUTH CHALLENGE")
		for _, p := range authInv.ProtectedEndpoints {
			challenge := p.AuthChallenge
			if challenge == "" {
				challenge = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
				p.Method, p.EndpointPath, p.ObservedStatus, p.ProtectionStatus, challenge)
		}
		_ = w.Flush()
	}

	fmt.Println()
	return 0
}

func printAuthzHelp() {
	fmt.Println("Usage: felix assessment authz <assessment-ref> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --policy <path>          Path to authorization policy file (JSON)")
	fmt.Println("  --run                    Execute planned authorization test cases against target")
	fmt.Println("  --dry-run                Display planned test cases without executing network requests")
	fmt.Println("  --category, -c <string>  Filter by category (BOLA, BFLA, BOPLA, HORIZONTAL, VERTICAL)")
	fmt.Println("  --status, -s <string>    Filter by verification state (VERIFIED, CANDIDATE, INCONCLUSIVE, NOT_VULNERABLE)")
	fmt.Println("  --verbose, -v            Display extended evidence details, observed status, and diffs")
	fmt.Println("  --json                   Output authorization intelligence as JSON")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment authz <asm-ref> --policy policy.json --dry-run")
	fmt.Println("  felix assessment authz <asm-ref> --policy policy.json --run")
	fmt.Println("  felix assessment authz <asm-ref> --status VERIFIED --verbose")
	fmt.Println("  felix assessment authz <asm-ref> --json")
}

func runAssessmentAuthz(args []string) int {
	var (
		assessmentRef  string
		policyPath     string
		runExecution   bool
		dryRun         bool
		categoryFilter string
		statusFilter   string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--policy":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--category" || arg == "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printAuthzHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	// 1. Dry Run Mode
	if dryRun {
		if policyPath == "" {
			fmt.Fprintf(os.Stderr, "[-] Error: --policy <file> is required for --dry-run\n")
			return 2
		}
		policy, err := authz.LoadPolicyFromFile(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load policy: %v\n", err)
			return 1
		}
		targetBase := "https://example.com"
		if len(asm.Targets) > 0 {
			targetBase = asm.Targets[0].TargetURL
		}
		planner := authz.NewPlanner(policy)
		planned := planner.PlanTestCases(targetBase)

		fmt.Println("===========================================================")
		fmt.Printf("  FELIX :: AUTHORIZATION TEST PLAN (DRY-RUN): %s\n", asm.Ref)
		fmt.Printf("  Identities: %d | Resources: %d | Planned Tests: %d\n", len(policy.Identities), len(policy.Resources), len(planned))
		fmt.Println("===========================================================")

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CATEGORY\tMETHOD\tENDPOINT\tPRIMARY IDENTITY\tEXPECTED\tDESCRIPTION")
		for _, tc := range planned {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				tc.Category, tc.Method, tc.Endpoint, tc.PrimaryIdentity, tc.ExpectedResult, tc.Description)
		}
		_ = w.Flush()
		fmt.Println()
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: no authorization record found for assessment %s\n", asm.Ref)
			return 1
		}
		valid, reason := asm.Authorization.IsCurrentlyValid(time.Now().UTC())
		if !valid {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: authorization invalid: %s\n", reason)
			return 1
		}

		var policy *authz.AuthzPolicy
		if policyPath != "" {
			p, err := authz.LoadPolicyFromFile(policyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to load policy from %s: %v\n", policyPath, err)
				return 1
			}
			policy = p
			if err := store.SaveAuthzPolicy(asm.ID, policy); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save policy to store: %v\n", err)
			}
		} else {
			p, err := store.GetAuthzPolicy(asm.ID)
			if err != nil || p == nil {
				fmt.Fprintf(os.Stderr, "[-] Error: no authorization policy found for assessment %s. Provide --policy <path>.\n", asm.Ref)
				return 2
			}
			policy = p
		}

		if len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: assessment %s has no targets configured\n", asm.Ref)
			return 1
		}

		targetURL := asm.Targets[0].TargetURL
		targetID := asm.Targets[0].ID

		execID := "exec-" + uuid.New().String()
		now := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    now,
			ConfigSnapshot: assessment.ScanConfigSnapshot{
				TimeoutSeconds: 15,
				Concurrency:    5,
				ScopeMode:      asm.ScopeMode,
				FelixVersion:   "2.0",
			},
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create execution record: %v\n", err)
			return 1
		}

		var targetURLs []string
		for _, t := range asm.Targets {
			targetURLs = append(targetURLs, t.TargetURL)
		}
		scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)
		authzHTTPClient := &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				lastURL := ""
				if len(via) > 0 {
					lastURL = via[len(via)-1].URL.String()
				}
				return scopeVal.ValidateRedirect(lastURL, req.URL.String())
			},
		}
		engine := authz.NewEngine(authzHTTPClient)

		fmt.Println("===========================================================")
		fmt.Printf("  EXECUTING AUTHORIZATION AUDIT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("  Target: %s | Write Tests Allowed: %t\n", targetURL, policy.AllowWriteTests)
		fmt.Println("===========================================================")

		startTime := time.Now()
		results, findings, summary, err := engine.Execute(
			context.Background(),
			targetURL,
			policy,
			asm.ID,
			execID,
			scopeVal.IsAllowed,
			func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			execRecord.ErrorMessage = err.Error()
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		duration := time.Since(startTime)
		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		execRecord.DurationMs = duration.Milliseconds()
		execRecord.RequestCount = len(results)
		execRecord.FindingCount = len(findings)

		if err := store.SaveAuthzResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save authz results: %v\n", err)
		}

		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save findings: %v\n", err)
			}
		}
		_ = store.UpdateExecution(execRecord)

		fmt.Printf("[✓] Authorization assessment completed in %s (%d tests executed, %d verified findings)\n",
			duration.Round(time.Millisecond), len(results), summary.VerifiedCount)
	}

	// 3. Display Results Mode
	results, err := store.GetAuthzResults(asm.ID, "", categoryFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch authz results: %v\n", err)
		return 1
	}

	summary, _ := store.GetAuthzSummary(asm.ID, "")

	if statusFilter != "" {
		var filtered []authz.AuthzTestResult
		for _, r := range results {
			if strings.EqualFold(string(r.VerificationState), statusFilter) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		output := map[string]any{
			"assessment_ref": asm.Ref,
			"assessment_id":  asm.ID,
			"summary":        summary,
			"results":        results,
		}
		_ = enc.Encode(output)
		return 0
	}

	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: AUTHORIZATION INTELLIGENCE: %s\n", asm.Ref)
	fmt.Printf("  Assessment Name: %s | Client ID: %s\n", asm.Name, asm.ClientID)
	fmt.Println("===========================================================")
	if summary != nil {
		fmt.Printf("  Total Tests:            %d\n", summary.TotalTests)
		fmt.Printf("  Verified Vulnerabilities: %d\n", summary.VerifiedCount)
		fmt.Printf("  Not Vulnerable (Enforced): %d\n", summary.NotVulnerableCount)
		fmt.Printf("  Candidates / Inconclusive: %d / %d\n", summary.CandidateCount, summary.InconclusiveCount)
		if len(summary.CategoryBreakdown) > 0 {
			fmt.Print("  Category Breakdown:     ")
			var catParts []string
			for k, v := range summary.CategoryBreakdown {
				catParts = append(catParts, fmt.Sprintf("%s=%d", k, v))
			}
			fmt.Println(strings.Join(catParts, ", "))
		}
		fmt.Println("-----------------------------------------------------------")
	}

	if len(results) > 0 {
		fmt.Printf("\n[+] AUTHORIZATION TEST RESULTS (%d)\n", len(results))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CATEGORY\tSTATE\tMETHOD\tENDPOINT\tIDENTITY\tSTATUS\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\tHTTP %d\t%s\n",
					r.Category, r.VerificationState, r.Method, r.Endpoint, r.PrimaryIdentity, r.ObservedStatus, r.EvidenceSummary)
			}
		} else {
			fmt.Fprintln(w, "CATEGORY\tSTATE\tMETHOD\tENDPOINT\tIDENTITY\tRESULT SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.Category, r.VerificationState, r.Method, r.Endpoint, r.PrimaryIdentity, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else {
		fmt.Println("\nNo authorization test results recorded.")
		fmt.Printf("To execute an authorization audit, run:\n  felix assessment authz %s --policy <policy.json> --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

func printAPISecHelp() {
	fmt.Println("Usage: felix assessment apisec <assessment-ref> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --run                    Execute OWASP API Security assessment against authorized targets")
	fmt.Println("  --dry-run                Display planned tests and inventory analysis without network requests")
	fmt.Println("  --spec <path>            Path to declared OpenAPI / Swagger JSON or routes specification")
	fmt.Println("  --policy <path>          Path to authorization policy file (JSON) for multi-user tests")
	fmt.Println("  --category, -c <string>  Filter results by OWASP category code or key (e.g. API1, API4, BOLA)")
	fmt.Println("  --status, -s <string>    Filter by verification state (VERIFIED, CANDIDATE, OBSERVED, NOT_VULNERABLE)")
	fmt.Println("  --canary <url>           Approved callback URL for SSRF canary verification (API7)")
	fmt.Println("  --verbose, -v            Display extended evidence details and audit observations")
	fmt.Println("  --json                   Output API security assessment findings and coverage as JSON")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment apisec <asm-ref> --dry-run --spec openapi.json")
	fmt.Println("  felix assessment apisec <asm-ref> --run --spec openapi.json --policy policy.json")
	fmt.Println("  felix assessment apisec <asm-ref> --status VERIFIED --verbose")
	fmt.Println("  felix assessment apisec <asm-ref> --category API1 --json")
}

func runAssessmentAPISec(args []string) int {
	var (
		assessmentRef  string
		specPath       string
		policyPath     string
		canaryURL      string
		runExecution   bool
		dryRun         bool
		categoryFilter string
		statusFilter   string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--spec":
			if i+1 < len(args) {
				specPath = args[i+1]
				i++
			}
		case arg == "--policy":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		case arg == "--canary":
			if i+1 < len(args) {
				canaryURL = args[i+1]
				i++
			}
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--category" || arg == "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printAPISecHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n")
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	targetBase := "https://example.com"
	if len(asm.Targets) > 0 {
		targetBase = asm.Targets[0].TargetURL
	}

	// Gather endpoints from discovered inventory
	var endpoints []apisec.APIEndpoint
	assets, _, _ := store.GetInventory(asm.ID, "", "ENDPOINT", false)
	for _, a := range assets {
		method := "GET"
		if m, ok := a.Metadata["method"].(string); ok && m != "" {
			method = m
		}
		path := a.DisplayName
		if p, ok := a.Metadata["path"].(string); ok && p != "" {
			path = p
		}
		endpoints = append(endpoints, apisec.AnalyzeEndpoint(method, path, "discovered"))
	}

	// Fallback endpoints if none discovered yet
	if len(endpoints) == 0 {
		endpoints = append(endpoints, apisec.AnalyzeEndpoint("GET", "/", "target_root"))
		endpoints = append(endpoints, apisec.AnalyzeEndpoint("GET", "/api/v1/health", "candidate"))
	}

	// Load declared spec if supplied
	var declaredSpec *apisec.DeclaredSpec
	if specPath != "" {
		ds, err := apisec.LoadDeclaredSpec(specPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to parse API specification from %s: %v\n", specPath, err)
		} else {
			declaredSpec = ds
		}
	}

	// Load authentication and authorization intelligence
	authInv, _ := store.GetAuthInventory(asm.ID, "", "")
	authzResults, _ := store.GetAuthzResults(asm.ID, "", "")

	var policy *authz.AuthzPolicy
	if policyPath != "" {
		p, err := authz.LoadPolicyFromFile(policyPath)
		if err == nil {
			policy = p
		}
	} else {
		policy, _ = store.GetAuthzPolicy(asm.ID)
	}

	// 1. Dry Run Mode
	if dryRun {
		fmt.Println("===========================================================")
		fmt.Printf("  FELIX :: OWASP API SECURITY PLAN (DRY-RUN): %s\n", asm.Ref)
		fmt.Printf("  Target Base: %s | Endpoints Analyzed: %d\n", targetBase, len(endpoints))
		fmt.Println("===========================================================")

		fmt.Println("\n[+] PREREQUISITE ASSESSMENT:")
		policyStatus := "MISSING (API1 BOLA, API3 BOPLA, API5 BFLA active tests skipped)"
		if policy != nil {
			policyStatus = fmt.Sprintf("PRESENT (%d identities, %d resources)", len(policy.Identities), len(policy.Resources))
		}
		fmt.Printf("  - Multi-User Authz Policy: %s\n", policyStatus)

		specStatus := "MISSING (API9 shadow API detection limited to version analysis)"
		if declaredSpec != nil {
			specStatus = fmt.Sprintf("LOADED (%d declared routes)", len(declaredSpec.Endpoints))
		}
		fmt.Printf("  - OpenAPI / API Spec:      %s\n", specStatus)

		canaryStatus := "NOT CONFIGURED (API7 SSRF tests limited to parameter discovery)"
		if canaryURL != "" {
			canaryStatus = fmt.Sprintf("CONFIGURED (%s)", canaryURL)
		}
		fmt.Printf("  - SSRF Canary Callback:    %s\n", canaryStatus)

		fmt.Println("\n[+] ENDPOINT ATTACK SURFACE CLASSIFICATION:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "METHOD\tPATH\tOBJECT REF\tPRIVILEGED\tFLOW\tSSRF\tPAGINATION")
		for _, ep := range endpoints {
			flowStr := "-"
			if ep.IsBusinessFlow {
				flowStr = ep.BusinessFlow
			}
			ssrfStr := "-"
			if ep.HasURLParam {
				ssrfStr = ep.URLParamName
			}
			pageStr := "-"
			if ep.HasPagination {
				pageStr = ep.PaginationParam
			}
			fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%s\t%s\t%s\n",
				ep.Method, ep.Path, ep.IsObjectRef, ep.IsPrivileged, flowStr, ssrfStr, pageStr)
		}
		_ = w.Flush()
		fmt.Println()
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: no authorization record found for assessment %s\n", asm.Ref)
			return 1
		}
		valid, reason := asm.Authorization.IsCurrentlyValid(time.Now().UTC())
		if !valid {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: authorization invalid: %s\n", reason)
			return 1
		}

		if len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: assessment %s has no targets configured\n", asm.Ref)
			return 1
		}

		targetID := asm.Targets[0].ID
		execID := "exec-" + uuid.New().String()
		now := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    now,
			ConfigSnapshot: assessment.ScanConfigSnapshot{
				TimeoutSeconds: 15,
				Concurrency:    5,
				ScopeMode:      asm.ScopeMode,
				FelixVersion:   "2.0",
			},
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create execution record: %v\n", err)
			return 1
		}

		var targetURLs []string
		for _, t := range asm.Targets {
			targetURLs = append(targetURLs, t.TargetURL)
		}
		scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)

		cfg := apisec.DefaultConfig()
		if canaryURL != "" {
			cfg.CanaryCallbackURL = canaryURL
		}
		if policy != nil && policy.AllowWriteTests {
			cfg.AllowWriteTests = true
		}
		apisecHTTPClient := &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				lastURL := ""
				if len(via) > 0 {
					lastURL = via[len(via)-1].URL.String()
				}
				return scopeVal.ValidateRedirect(lastURL, req.URL.String())
			},
		}
		engine := apisec.NewEngine(apisecHTTPClient, cfg)
		actx := &apisec.AssessmentContext{
			AssessmentID: asm.ID,
			ExecutionID:  execID,
			BaseURL:      targetBase,
			Endpoints:    endpoints,
			AuthInv:      authInv,
			AuthzPolicy:  policy,
			AuthzResults: authzResults,
			DeclaredSpec: declaredSpec,
			IsAllowed:    scopeVal.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		}

		fmt.Println("===========================================================")
		fmt.Printf("  EXECUTING OWASP API SECURITY AUDIT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("  Target: %s | Endpoints: %d\n", targetBase, len(endpoints))
		fmt.Println("===========================================================")

		startTime := time.Now()
		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			execRecord.ErrorMessage = err.Error()
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		duration := time.Since(startTime)
		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		execRecord.DurationMs = duration.Milliseconds()
		execRecord.RequestCount = len(results)
		execRecord.FindingCount = len(findings)

		// Save results
		if err := store.SaveAPISecResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save apisec results: %v\n", err)
		}

		// Save RunRecord
		covJSON, _ := json.Marshal(summary.CoverageMap)
		runRec := &apisec.RunRecord{
			ID:                 uuid.New().String(),
			AssessmentID:       asm.ID,
			ExecutionID:        execID,
			TotalTests:         summary.TotalTests,
			CategoriesAssessed: summary.CategoriesCovered,
			VerifiedCount:      summary.VerifiedCount,
			CandidateCount:     summary.CandidateCount,
			ObservedCount:      summary.ObservedCount,
			CoverageJSON:       string(covJSON),
			CreatedAt:          completedAt,
		}
		if err := store.SaveAPISecRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save apisec run record: %v\n", err)
		}

		// Save findings
		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save assessment findings: %v\n", err)
			}
		}
		_ = store.UpdateExecution(execRecord)

		fmt.Printf("[✓] API Security assessment completed in %s (%d tests executed, %d verified findings)\n",
			duration.Round(time.Millisecond), summary.TotalTests, summary.VerifiedCount)
	}

	// 3. Display Results Mode
	results, err := store.GetAPISecResults(asm.ID, "", categoryFilter, statusFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch apisec results: %v\n", err)
		return 1
	}

	summary, _ := store.GetAPISecSummary(asm.ID, "")

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		output := map[string]any{
			"assessment_ref": asm.Ref,
			"assessment_id":  asm.ID,
			"summary":        summary,
			"results":        results,
		}
		_ = enc.Encode(output)
		return 0
	}

	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: OWASP API SECURITY TOP 10 (2023): %s\n", asm.Ref)
	fmt.Printf("  Assessment: %s | Target: %s\n", asm.Name, targetBase)
	fmt.Println("===========================================================")

	if summary != nil && len(summary.CoverageMap) > 0 {
		fmt.Printf("  Total Tests Run:          %d\n", summary.TotalTests)
		fmt.Printf("  Verified Vulnerabilities: %d\n", summary.VerifiedCount)
		fmt.Printf("  Candidate Issues:         %d\n", summary.CandidateCount)
		fmt.Printf("  Observations:             %d\n", summary.ObservedCount)
		fmt.Printf("  Not Vulnerable / Defended:%d\n", summary.NotVulnerableCount)
		fmt.Println("-----------------------------------------------------------")

		fmt.Println("\n[+] OWASP API SECURITY TOP 10 COVERAGE MATRIX:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CODE\tCATEGORY\tSTATUS\tTESTS\tVERIFIED\tCANDIDATES\tOBSERVED\tEXPLANATION")

		// Sort or iterate consistently
		categories := []apisec.OWASPCategory{
			apisec.CategoryAPI1_BOLA,
			apisec.CategoryAPI2_BrokenAuth,
			apisec.CategoryAPI3_BOPLA,
			apisec.CategoryAPI4_ResourceConsumption,
			apisec.CategoryAPI5_BFLA,
			apisec.CategoryAPI6_BusinessFlows,
			apisec.CategoryAPI7_SSRF,
			apisec.CategoryAPI8_Misconfiguration,
			apisec.CategoryAPI9_ImproperInventory,
			apisec.CategoryAPI10_UnsafeConsumption,
		}

		for _, cat := range categories {
			cov, ok := summary.CoverageMap[string(cat)]
			if !ok {
				meta := apisec.OWASPCategoryMetadata[cat]
				cov = apisec.CategoryCoverage{
					Code:        meta.Code,
					Name:        meta.Name,
					Status:      apisec.CoverageUntested,
					Explanation: "Untested",
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
				cov.Code, cov.Name, cov.Status, cov.TestsRun, cov.Verified, cov.Candidates, cov.Observations, cov.Explanation)
		}
		_ = w.Flush()
	}

	if len(results) > 0 {
		fmt.Printf("\n[+] API SECURITY TEST RESULTS (%d)\n", len(results))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CODE\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tTEST NAME\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.OWASPCode, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.TestName, r.EvidenceSummary)
			}
		} else {
			fmt.Fprintln(w, "CODE\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.OWASPCode, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else if summary == nil || summary.TotalTests == 0 {
		fmt.Println("\nNo API security test results recorded.")
		fmt.Printf("To run an API security assessment:\n  felix assessment apisec %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

func printWebVulnHelp() {
	fmt.Println("Usage: felix assessment webvuln <assessment-ref> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --dry-run              Display vulnerability assessment execution plan without making active requests (default)")
	fmt.Println("  --run                  Execute controlled web vulnerability testing pipeline")
	fmt.Println("  -c, --category <name>  Filter results by category (XSS, SQLI, NOSQLI, CMDI, PATH_TRAVERSAL, SSTI, SSRF, OPEN_REDIRECT, etc.)")
	fmt.Println("  -s, --status <state>   Filter results by verification state (VERIFIED, CANDIDATE, OBSERVED, NOT_VULNERABLE)")
	fmt.Println("  --canary <url>         Public canary callback URL for SSRF out-of-band verification")
	fmt.Println("  -v, --verbose          Display detailed evidence summaries")
	fmt.Println("  --json                 Output machine-readable JSON")
	fmt.Println("  -h, --help             Display this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment webvuln <asm-ref> --dry-run")
	fmt.Println("  felix assessment webvuln <asm-ref> --run")
	fmt.Println("  felix assessment webvuln <asm-ref> --category XSS --status VERIFIED")
	fmt.Println("  felix assessment webvuln <asm-ref> --json")
}

func runAssessmentWebVuln(args []string) int {
	var (
		assessmentRef  string
		runExecution   bool
		dryRun         bool
		categoryFilter string
		statusFilter   string
		canaryURL      string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--category" || arg == "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--canary":
			if i+1 < len(args) {
				canaryURL = args[i+1]
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printWebVulnHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n\n")
		printWebVulnHelp()
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error finding assessment '%s': %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	targetBase := "http://localhost"
	if len(asm.Targets) > 0 {
		targetBase = strings.TrimRight(asm.Targets[0].TargetURL, "/")
	}

	// Load inventory endpoints and parameters
	assets, _, _ := store.GetInventory(asm.ID, "", "", true)
	var targetEndpoints []webvuln.TargetEndpoint
	seenEndpoints := make(map[string]bool)

	for _, a := range assets {
		if a.Type == "ENDPOINT" || a.Type == "endpoint" {
			method := "GET"
			if m, ok := a.Metadata["method"].(string); ok && m != "" {
				method = strings.ToUpper(m)
			}
			path := a.DisplayName
			if p, ok := a.Metadata["path"].(string); ok && p != "" {
				path = p
			} else if a.CanonicalID != "" {
				path = a.CanonicalID
			}
			if strings.Contains(path, " ") {
				parts := strings.SplitN(path, " ", 2)
				if len(parts) == 2 {
					if method == "GET" || method == "UNKNOWN" {
						method = strings.ToUpper(parts[0])
					}
					path = parts[1]
				}
			}
			if method == "UNKNOWN" {
				method = "GET"
			}
			if u, err := url.Parse(path); err == nil && u.Path != "" {
				path = u.Path
			}

			var params []string
			if pList, ok := a.Metadata["params"].([]any); ok {
				for _, p := range pList {
					if ps, ok := p.(string); ok && ps != "" {
						params = append(params, ps)
					}
				}
			}
			key := method + " " + path
			if !seenEndpoints[key] {
				seenEndpoints[key] = true
				targetEndpoints = append(targetEndpoints, webvuln.TargetEndpoint{
					Method:     method,
					Path:       path,
					Parameters: params,
					Source:     "inventory",
				})
			}
		}
	}

	if len(targetEndpoints) == 0 {
		targetEndpoints = append(targetEndpoints, webvuln.TargetEndpoint{
			Method: "GET",
			Path:   "/",
			Source: "target_root",
		})
	}

	// Check if existing results exist
	existingResults, _ := store.GetWebVulnResults(asm.ID, "", "", "")
	if !runExecution && !dryRun && len(existingResults) == 0 {
		dryRun = true
	}

	// 1. Dry Run Mode
	if dryRun {
		fmt.Println("===========================================================")
		fmt.Printf("  FELIX :: WEB VULNERABILITY ENGINE PLAN (DRY-RUN): %s\n", asm.Ref)
		fmt.Printf("  Assessment: %s | Target Base: %s\n", asm.Name, targetBase)
		fmt.Printf("  Endpoints Loaded: %d | Categories Supported: 13\n", len(targetEndpoints))
		fmt.Println("===========================================================")

		fmt.Println("\n[+] SAFETY & VERIFICATION BOUNDARIES:")
		fmt.Println("  - OS Command Injection: Strictly passive / synthetic fixture only (zero live command execution)")
		fmt.Println("  - Path Traversal:       Strictly bounded non-sensitive canary indicators (zero live credential dumps)")
		fmt.Println("  - File Inclusion:       Controlled static analysis only (zero remote attacker payload execution)")
		fmt.Println("  - SSTI:                 Safe arithmetic proofs only ({{491*13}} -> 6383); literal reflections NOT vulnerable")
		fmt.Println("  - XSS:                  Inert canaries checked in executable HTML body; encoded/JSON not marked verified")
		fmt.Println("  - SQLi:                 Database-specific syntax error proof vs baseline; generic 500 marked candidate")
		fmt.Println("  - SSRF:                 Private and cloud metadata IP ranges blocked; callback canary required")
		fmt.Println("  - Request Smuggling:    Active desynchronization disabled by default; passive normalization only")

		fmt.Println("\n[+] SUPPORTED VULNERABILITY CATEGORIES (13):")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CODE\tCATEGORY\tCWE\tVERIFICATION STANDARD")
		for _, cat := range []webvuln.VulnCategory{
			webvuln.CategoryXSS, webvuln.CategorySQLi, webvuln.CategoryNoSQLi,
			webvuln.CategoryCmdi, webvuln.CategoryPathTraversal, webvuln.CategoryFileInclusion,
			webvuln.CategorySSTI, webvuln.CategorySSRF, webvuln.CategoryOpenRedirect,
			webvuln.CategoryRequestIssues, webvuln.CategoryInfoDisclosure,
			webvuln.CategoryDeserialization, webvuln.CategoryMisconfiguration,
		} {
			meta := webvuln.CategoryMetadata[cat]
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", meta.Code, meta.Name, meta.CWE, meta.VerificationBoundary)
		}
		_ = w.Flush()

		fmt.Println("\n[+] TARGET ENDPOINTS TO EVALUATE:")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "METHOD\tPATH\tPARAMETERS\tSOURCE")
		for _, ep := range targetEndpoints {
			pStr := "-"
			if len(ep.Parameters) > 0 {
				pStr = strings.Join(ep.Parameters, ", ")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ep.Method, ep.Path, pStr, ep.Source)
		}
		_ = w.Flush()
		fmt.Printf("\nTo execute controlled testing:\n  felix assessment webvuln %s --run\n\n", asm.Ref)
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: no authorization record found for assessment %s\n", asm.Ref)
			return 1
		}
		valid, reason := asm.Authorization.IsCurrentlyValid(time.Now().UTC())
		if !valid {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: authorization invalid: %s\n", reason)
			return 1
		}

		if len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: assessment %s has no targets configured\n", asm.Ref)
			return 1
		}

		targetID := asm.Targets[0].ID
		execID := "exec-" + uuid.New().String()
		now := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    now,
			ConfigSnapshot: assessment.ScanConfigSnapshot{
				TimeoutSeconds: 15,
				Concurrency:    5,
				ScopeMode:      asm.ScopeMode,
				FelixVersion:   "2.0",
			},
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create execution record: %v\n", err)
			return 1
		}

		var targetURLs []string
		for _, t := range asm.Targets {
			targetURLs = append(targetURLs, t.TargetURL)
		}
		scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)

		cfg := webvuln.DefaultConfig()
		if canaryURL != "" {
			cfg.CanaryCallbackURL = canaryURL
		}

		webvulnHTTPClient := &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				lastURL := ""
				if len(via) > 0 {
					lastURL = via[len(via)-1].URL.String()
				}
				return scopeVal.ValidateRedirect(lastURL, req.URL.String())
			},
		}
		engine := webvuln.NewEngine(webvulnHTTPClient, cfg)
		actx := &webvuln.AssessmentContext{
			AssessmentID: asm.ID,
			ExecutionID:  execID,
			BaseURL:      targetBase,
			Endpoints:    targetEndpoints,
			IsAllowed:    scopeVal.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		}

		fmt.Println("===========================================================")
		fmt.Printf("  EXECUTING WEB VULNERABILITY AUDIT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("  Target: %s | Endpoints: %d\n", targetBase, len(targetEndpoints))
		fmt.Println("===========================================================")

		startTime := time.Now()
		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			execRecord.ErrorMessage = err.Error()
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		duration := time.Since(startTime)
		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		execRecord.DurationMs = duration.Milliseconds()
		execRecord.RequestCount = len(results)
		execRecord.FindingCount = len(findings)

		// Save results
		if err := store.SaveWebVulnResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save webvuln results: %v\n", err)
		}

		// Save RunRecord
		covJSON, _ := json.Marshal(summary.CoverageMap)
		runRec := &webvuln.RunRecord{
			ID:                 uuid.New().String(),
			AssessmentID:       asm.ID,
			ExecutionID:        execID,
			TotalTests:         summary.TotalTests,
			CategoriesAssessed: summary.CategoriesCovered,
			VerifiedCount:      summary.VerifiedCount,
			CandidateCount:     summary.CandidateCount,
			ObservedCount:      summary.ObservedCount,
			CoverageJSON:       string(covJSON),
			CreatedAt:          completedAt,
		}
		if err := store.SaveWebVulnRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save webvuln run record: %v\n", err)
		}

		// Save findings
		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save assessment findings: %v\n", err)
			}
		}
		_ = store.UpdateExecution(execRecord)

		fmt.Printf("[✓] Web vulnerability audit completed in %s (%d tests executed, %d verified findings)\n",
			duration.Round(time.Millisecond), summary.TotalTests, summary.VerifiedCount)
	}

	// 3. Display Results Mode
	results, err := store.GetWebVulnResults(asm.ID, "", categoryFilter, statusFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch webvuln results: %v\n", err)
		return 1
	}

	summary, _ := store.GetWebVulnSummary(asm.ID, "")

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		output := map[string]any{
			"assessment_ref": asm.Ref,
			"assessment_id":  asm.ID,
			"summary":        summary,
			"results":        results,
		}
		_ = enc.Encode(output)
		return 0
	}

	fmt.Println("===========================================================")
	fmt.Printf("  FELIX :: WEB VULNERABILITY ASSESSMENT DOSSIER: %s\n", asm.Ref)
	fmt.Printf("  Assessment: %s | Target: %s\n", asm.Name, targetBase)
	fmt.Println("===========================================================")

	if summary != nil {
		fmt.Println("\n[+] SUMMARY METRICS:")
		fmt.Printf("  - Total Tests Executed:     %d\n", summary.TotalTests)
		fmt.Printf("  - Categories Covered:       %d / 13\n", summary.CategoriesCovered)
		fmt.Printf("  - Verified Vulnerabilities: %d\n", summary.VerifiedCount)
		fmt.Printf("  - Candidate Vulnerabilities:%d\n", summary.CandidateCount)
		fmt.Printf("  - Observed Patterns:        %d\n", summary.ObservedCount)
		fmt.Printf("  - Not Vulnerable / Safe:    %d\n", summary.NotVulnerableCount)

		fmt.Println("\n[+] CATEGORY COVERAGE MATRIX:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CODE\tCATEGORY\tSTATUS\tTESTS\tVERIFIED\tCANDIDATES\tOBSERVED\tEXPLANATION")
		for _, cat := range []webvuln.VulnCategory{
			webvuln.CategoryXSS, webvuln.CategorySQLi, webvuln.CategoryNoSQLi,
			webvuln.CategoryCmdi, webvuln.CategoryPathTraversal, webvuln.CategoryFileInclusion,
			webvuln.CategorySSTI, webvuln.CategorySSRF, webvuln.CategoryOpenRedirect,
			webvuln.CategoryRequestIssues, webvuln.CategoryInfoDisclosure,
			webvuln.CategoryDeserialization, webvuln.CategoryMisconfiguration,
		} {
			cov, ok := summary.CoverageMap[string(cat)]
			if !ok {
				meta := webvuln.CategoryMetadata[cat]
				cov = webvuln.CategoryCoverage{Code: meta.Code, Name: meta.Name, Status: webvuln.CoverageUntested}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
				cov.Code, cov.Name, cov.Status, cov.TestsRun, cov.Verified, cov.Candidates, cov.Observations, cov.Explanation)
		}
		_ = w.Flush()
	}

	if len(results) > 0 {
		fmt.Printf("\n[+] WEB VULNERABILITY TEST RESULTS (%d)\n", len(results))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CODE\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tTEST NAME\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.VulnCode, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.TestName, r.EvidenceSummary)
			}
		} else {
			fmt.Fprintln(w, "CODE\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.VulnCode, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else if summary == nil || summary.TotalTests == 0 {
		fmt.Println("\nNo web vulnerability test results recorded.")
		fmt.Printf("To run a web vulnerability assessment:\n  felix assessment webvuln %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

// -------------------------------------------------------------------------
// Stage 7: Session & Identity Security CLI Implementation
// -------------------------------------------------------------------------

func printSessionSecHelp() {
	fmt.Println("Usage: felix assessment sessionsec <assessment-ref> [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --run                    Execute active session & identity security assessment")
	fmt.Println("  --dry-run                Plan tests, analyze state transitions, and verify preconditions")
	fmt.Println("  --policy <path>          Path to authorization policy file (JSON) with test identities")
	fmt.Println("  --category, -c <cat>     Filter by session category (FIXATION, COOKIE, INVALIDATION, etc.)")
	fmt.Println("  --status, -s <state>     Filter by verification state (VERIFIED, CANDIDATE, OBSERVED, NOT_VULNERABLE)")
	fmt.Println("  --json                   Output full JSON format")
	fmt.Println("  --verbose, -v            Show detailed evidence, state transitions, and boundaries")
	fmt.Println("  --help, -h               Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment sessionsec <asm-ref> --dry-run")
	fmt.Println("  felix assessment sessionsec <asm-ref> --run")
	fmt.Println("  felix assessment sessionsec <asm-ref> --run --policy policy.json")
	fmt.Println("  felix assessment sessionsec <asm-ref> --status VERIFIED")
	fmt.Println("  felix assessment sessionsec <asm-ref> --category SESSION_FIXATION --json")
}

func runAssessmentSessionSec(args []string) int {
	var (
		assessmentRef  string
		runExecution   bool
		dryRun         bool
		policyPath     string
		categoryFilter string
		statusFilter   string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--policy":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		case arg == "--category" || arg == "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printSessionSecHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n\n")
		printSessionSecHelp()
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error finding assessment '%s': %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	targetBase := "http://localhost"
	if len(asm.Targets) > 0 {
		targetBase = strings.TrimRight(asm.Targets[0].TargetURL, "/")
	}

	// Load inventory endpoints and auth surfaces
	assets, _, _ := store.GetInventory(asm.ID, "", "", true)
	authInv, _ := store.GetAuthInventory(asm.ID, "", "")

	var targetEndpoints []sessionsec.TargetEndpoint
	seenEndpoints := make(map[string]bool)

	// Add endpoints from attack-surface inventory
	for _, a := range assets {
		if a.Type == "ENDPOINT" || a.Type == "endpoint" {
			method := "GET"
			if m, ok := a.Metadata["method"].(string); ok && m != "" {
				method = strings.ToUpper(m)
			}
			path := a.DisplayName
			if p, ok := a.Metadata["path"].(string); ok && p != "" {
				path = p
			} else if a.CanonicalID != "" {
				path = a.CanonicalID
			}
			if strings.Contains(path, " ") {
				parts := strings.SplitN(path, " ", 2)
				if len(parts) == 2 {
					if method == "GET" || method == "UNKNOWN" {
						method = strings.ToUpper(parts[0])
					}
					path = parts[1]
				}
			}
			if method == "UNKNOWN" {
				method = "GET"
			}
			if u, err := url.Parse(path); err == nil && u.Path != "" {
				path = u.Path
			}

			key := method + " " + path
			if !seenEndpoints[key] {
				seenEndpoints[key] = true
				epType := "public"
				lower := strings.ToLower(path)
				switch {
				case strings.Contains(lower, "login") || strings.Contains(lower, "signin"):
					epType = "login"
				case strings.Contains(lower, "logout") || strings.Contains(lower, "signout"):
					epType = "logout"
				case strings.Contains(lower, "reset") || strings.Contains(lower, "recover") || strings.Contains(lower, "forgot"):
					epType = "recovery"
				case strings.Contains(lower, "refresh") || strings.Contains(lower, "token"):
					epType = "refresh"
				case strings.Contains(lower, "step") || strings.Contains(lower, "verify") || strings.Contains(lower, "onboard"):
					epType = "multistep"
				case strings.Contains(lower, "profile") || strings.Contains(lower, "account") || strings.Contains(lower, "dashboard") || strings.Contains(lower, "admin") || strings.Contains(lower, "user"):
					epType = "protected"
				}

				targetEndpoints = append(targetEndpoints, sessionsec.TargetEndpoint{
					Method: method,
					Path:   path,
					Type:   epType,
					Source: "inventory",
				})
			}
		}
	}

	// Add endpoints from auth inventory surfaces
	if authInv != nil {
		for _, surf := range authInv.Surfaces {
			path := surf.Identifier
			if path != "" {
				if u, err := url.Parse(path); err == nil && u.Path != "" {
					path = u.Path
				}
				method := "GET"
				if m, ok := surf.Metadata["method"].(string); ok && m != "" {
					method = strings.ToUpper(m)
				}
				key := method + " " + path
				if !seenEndpoints[key] {
					seenEndpoints[key] = true
					epType := "public"
					switch surf.Category {
					case auth.CategoryLogin:
						epType = "login"
					case auth.CategoryPasswordReset:
						epType = "recovery"
					case auth.CategorySession:
						if strings.Contains(strings.ToLower(path), "logout") {
							epType = "logout"
						} else {
							epType = "protected"
						}
					case auth.CategoryOAuthSSO:
						epType = "refresh"
					case auth.CategoryProtectedEndpoint:
						epType = "protected"
					}
					targetEndpoints = append(targetEndpoints, sessionsec.TargetEndpoint{
						Method: method,
						Path:   path,
						Type:   epType,
						Source: "auth_surface",
					})
				}
			}
		}
	}

	// Fallback sensible endpoints if inventory has none
	if len(targetEndpoints) == 0 {
		targetEndpoints = append(targetEndpoints,
			sessionsec.TargetEndpoint{Method: "GET", Path: "/", Type: "public", Source: "default"},
			sessionsec.TargetEndpoint{Method: "POST", Path: "/login", Type: "login", Source: "default"},
			sessionsec.TargetEndpoint{Method: "POST", Path: "/logout", Type: "logout", Source: "default"},
			sessionsec.TargetEndpoint{Method: "GET", Path: "/profile", Type: "protected", Source: "default"},
		)
	}

	// Load identities from policy
	var policy *authz.AuthzPolicy
	if policyPath != "" {
		p, err := authz.LoadPolicyFromFile(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load policy from %s: %v\n", policyPath, err)
			return 1
		}
		policy = p
		_ = store.SaveAuthzPolicy(asm.ID, policy)
	} else {
		policy, _ = store.GetAuthzPolicy(asm.ID)
	}

	var identities []sessionsec.TestIdentity
	if policy != nil {
		for _, id := range policy.Identities {
			priv := id.PrivilegeLevel
			if priv == 0 {
				priv = 1
				if strings.EqualFold(id.Role, "admin") {
					priv = 10
				}
			}
			identities = append(identities, sessionsec.TestIdentity{
				Alias:          id.Alias,
				Role:           id.Role,
				TenantID:       id.TenantID,
				PrivilegeLevel: priv,
				Headers:        id.Headers,
				Cookies:        id.Cookies,
			})
		}
	}

	// Check if existing results exist
	existingResults, _ := store.GetSessionSecResults(asm.ID, "", "", "")
	if !runExecution && !dryRun && len(existingResults) == 0 {
		dryRun = true
	}

	// 1. Dry Run Mode
	if dryRun {
		engine := sessionsec.NewEngine(nil, sessionsec.DefaultConfig())
		actx := &sessionsec.AssessmentContext{
			AssessmentID: asm.ID,
			BaseURL:      targetBase,
			Endpoints:    targetEndpoints,
			Identities:   identities,
		}
		plan, _ := engine.Plan(context.Background(), actx)

		if jsonOutput {
			b, _ := json.MarshalIndent(plan, "", "  ")
			fmt.Println(string(b))
			return 0
		}

		fmt.Println("================================================================================")
		fmt.Printf("  FELIX :: SESSION & IDENTITY SECURITY ENGINE PLAN (DRY-RUN): %s\n", asm.Ref)
		fmt.Printf("  Assessment: %s | Target Base: %s\n", asm.Name, targetBase)
		fmt.Printf("  Endpoints Loaded: %d | Test Identities: %d | Planned Tests: %d\n", len(targetEndpoints), len(identities), len(plan.Tests))
		fmt.Println("================================================================================")

		fmt.Println("\n[+] SAFETY & ZERO-PERSISTENCE GUARANTEES:")
		fmt.Println("  - Zero Credential Persistence:  Passwords, session IDs, and tokens are NEVER stored in plaintext.")
		fmt.Println("  - Token Rotation Verification:  State changes computed via one-way SHA-256 fingerprints in-memory.")
		fmt.Println("  - State Precondition Checks:   Tests requiring elevated or distinct roles fail-closed if unconfigured.")
		fmt.Println("  - Non-Destructive Testing:     Password reset lifecycle uses non-destructive token replay checks.")
		fmt.Println("  - Strict Scope Enforcement:    All requests and redirect destinations validated against approved scope.")

		fmt.Println("\n[+] PLANNED SESSION & IDENTITY TESTS (11 WSTG CATEGORIES):")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TEST ID\tCATEGORY\tWSTG REF\tSTATUS\tREQUIRED STATE\tBLOCK REASON")
		for _, t := range plan.Tests {
			reason := t.BlockedReason
			if reason == "" {
				reason = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				t.ID, t.Category, t.WSTGRef, t.Status, t.RequiredState, reason)
		}
		_ = w.Flush()

		fmt.Println("\n[+] TARGET ENDPOINTS DETECTED:")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "METHOD\tPATH\tROLE/TYPE\tSOURCE")
		for _, ep := range targetEndpoints {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ep.Method, ep.Path, ep.Type, ep.Source)
		}
		_ = w.Flush()

		fmt.Printf("\nTo execute active testing:\n  felix assessment sessionsec %s --run\n\n", asm.Ref)
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: no authorization record found for assessment %s\n", asm.Ref)
			return 1
		}
		valid, reason := asm.Authorization.IsCurrentlyValid(time.Now().UTC())
		if !valid {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: authorization invalid: %s\n", reason)
			return 1
		}

		if len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: assessment %s has no targets configured\n", asm.Ref)
			return 1
		}

		targetID := asm.Targets[0].ID
		execID := "exec-" + uuid.New().String()
		now := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    now,
			ConfigSnapshot: assessment.ScanConfigSnapshot{
				TimeoutSeconds: 15,
				Concurrency:    5,
				ScopeMode:      asm.ScopeMode,
				FelixVersion:   "2.0",
			},
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create execution record: %v\n", err)
			return 1
		}

		var targetURLs []string
		for _, t := range asm.Targets {
			targetURLs = append(targetURLs, t.TargetURL)
		}
		scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)

		cfg := sessionsec.DefaultConfig()
		sessionHTTPClient := &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				lastURL := ""
				if len(via) > 0 {
					lastURL = via[len(via)-1].URL.String()
				}
				return scopeVal.ValidateRedirect(lastURL, req.URL.String())
			},
		}

		engine := sessionsec.NewEngine(sessionHTTPClient, cfg)
		actx := &sessionsec.AssessmentContext{
			AssessmentID: asm.ID,
			ExecutionID:  execID,
			BaseURL:      targetBase,
			Endpoints:    targetEndpoints,
			Identities:   identities,
			IsAllowed:    scopeVal.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		}

		fmt.Println("================================================================================")
		fmt.Printf("  EXECUTING SESSION & IDENTITY SECURITY AUDIT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("  Target: %s | Endpoints: %d | Identities: %d\n", targetBase, len(targetEndpoints), len(identities))
		fmt.Println("================================================================================")

		startTime := time.Now()
		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			execRecord.ErrorMessage = err.Error()
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		duration := time.Since(startTime)
		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		execRecord.DurationMs = duration.Milliseconds()
		execRecord.RequestCount = len(results)
		execRecord.FindingCount = len(findings)

		// Save results
		if err := store.SaveSessionSecResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save sessionsec results: %v\n", err)
		}

		// Save RunRecord
		covJSON, _ := json.Marshal(summary.CoverageMap)
		runRec := &sessionsec.RunRecord{
			ID:                 uuid.New().String(),
			AssessmentID:       asm.ID,
			ExecutionID:        execID,
			TotalTests:         summary.TotalTests,
			CategoriesAssessed: summary.CategoriesCovered,
			VerifiedCount:      summary.VerifiedCount,
			CandidateCount:     summary.CandidateCount,
			ObservedCount:      summary.ObservedCount,
			InconclusiveCount:  summary.InconclusiveCount,
			BlockedCount:       summary.BlockedCount,
			CoverageJSON:       string(covJSON),
			CreatedAt:          completedAt,
		}
		if err := store.SaveSessionSecRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save sessionsec run record: %v\n", err)
		}

		// Save findings
		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save findings: %v\n", err)
			}
		}

		_ = store.UpdateExecution(execRecord)

		fmt.Printf("\n[+] Assessment Complete in %v\n", duration.Round(time.Millisecond))
		fmt.Printf("    Total Tests: %d | Categories Assessed: %d\n", summary.TotalTests, summary.CategoriesCovered)
		fmt.Printf("    Verified Issues: %d | Candidates: %d | Observations: %d\n",
			summary.VerifiedCount, summary.CandidateCount, summary.ObservedCount)
	}

	// 3. Reporting / Inspection Mode
	results, err := store.GetSessionSecResults(asm.ID, "", categoryFilter, statusFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch sessionsec results: %v\n", err)
		return 1
	}

	summary, _ := store.GetSessionSecSummary(asm.ID, "")

	if jsonOutput {
		out := map[string]interface{}{
			"assessment_ref": asm.Ref,
			"target_base":    targetBase,
			"summary":        summary,
			"results":        results,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	fmt.Println("\n================================================================================")
	fmt.Printf("  FELIX :: SESSION & IDENTITY SECURITY FINDINGS: %s\n", asm.Ref)
	fmt.Printf("  Target Base: %s\n", targetBase)
	fmt.Println("================================================================================")

	allCats := []sessionsec.SessionCategory{
		sessionsec.CategorySessionFixation,
		sessionsec.CategoryCookieSecurity,
		sessionsec.CategorySessionInvalidation,
		sessionsec.CategoryAuthStateInconsistency,
		sessionsec.CategoryTokenHandling,
		sessionsec.CategoryPrivilegeTransitions,
		sessionsec.CategoryLogoutBehavior,
		sessionsec.CategoryPasswordRecovery,
		sessionsec.CategoryAccountEnumeration,
		sessionsec.CategorySessionPuzzling,
		sessionsec.CategorySessionIsolation,
	}

	if summary != nil && len(summary.CoverageMap) > 0 {
		fmt.Println("\n[+] CATEGORY COVERAGE SUMMARY:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CODE\tCATEGORY\tWSTG REF\tSTATUS\tTESTS\tVERIFIED\tCANDIDATES")
		for _, cat := range allCats {
			cov, ok := summary.CoverageMap[string(cat)]
			if !ok {
				meta := sessionsec.CategoryMetadata[cat]
				cov = sessionsec.CategoryCoverage{
					Code:    meta.Code,
					Name:    meta.Name,
					WSTGRef: meta.WSTG,
					Status:  sessionsec.CoverageUntested,
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
				cov.Code, cov.Name, cov.WSTGRef, cov.Status, cov.TestsRun, cov.Verified, cov.Candidates)
		}
		_ = w.Flush()
	}

	if len(results) > 0 {
		fmt.Println("\n[+] DETAILED TEST RESULTS:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CODE\tWSTG\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tEVIDENCE & DETAILS")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.VulnCode, r.WSTGRef, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.EvidenceSummary)
			}
		} else {
			fmt.Fprintln(w, "CODE\tSTATE\tSEVERITY\tMETHOD\tENDPOINT\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.VulnCode, r.VerificationState, r.Severity, r.Method, r.Endpoint, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else if summary == nil || summary.TotalTests == 0 {
		fmt.Println("\nNo session security test results recorded.")
		fmt.Printf("To run a session & identity security assessment:\n  felix assessment sessionsec %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

func printCloudSecHelp() {
	fmt.Println("Usage: felix assessment cloudsec <asm-ref> [flags]")
	fmt.Println("\nReal Cloud Security Engine — AWS, Microsoft Azure & Google Cloud Platform")
	fmt.Println("External Assessment (Mode A) + Credentialed Cloud Assessment (Mode B)")
	fmt.Println("\nFlags:")
	fmt.Println("  --mode <mode>          Assessment mode: external (default) or credentialed")
	fmt.Println("  --provider <provider>  Target cloud provider: aws, azure, or gcp")
	fmt.Println("  --credentials <path>   Path to scoped credentials JSON file (never persisted or logged)")
	fmt.Println("  --scope <target-id>    Declared target scope (AWS Account ID, Azure Subscription ID, GCP Project ID)")
	fmt.Println("  --service <service>    Limit assessment or filtering to a specific service")
	fmt.Println("  --region <region>      Target cloud region (e.g. us-east-1, eastus, us-central1)")
	fmt.Println("  --dry-run              Generate and display planned checks without executing network requests")
	fmt.Println("  --run                  Execute active assessment against authorized cloud targets")
	fmt.Println("  --status <state>       Filter results by state: VERIFIED, CANDIDATE, OBSERVED, NOT_VULNERABLE")
	fmt.Println("  --json                 Output results as JSON")
	fmt.Println("  --verbose, -v          Show detailed evidence")
	fmt.Println("  --help, -h             Display this help message")
	fmt.Println("\nExternal Mode (Mode A):")
	fmt.Println("  Assesses external observable storage buckets, CDN origins, and API/function endpoints.")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode external --dry-run")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode external --run")
	fmt.Println("\nCredentialed Mode (Mode B):")
	fmt.Println("  Assesses configuration posture via authenticated read-only provider APIs.")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode credentialed --provider aws --credentials creds.json --scope 123456789012 --dry-run")
	fmt.Println("  felix assessment cloudsec <asm-ref> --mode credentialed --provider aws --credentials creds.json --scope 123456789012 --run")
}

func runAssessmentCloudSec(args []string) int {
	var (
		assessmentRef   string
		runExecution    bool
		dryRun          bool
		modeStr         string
		providerStr     string
		credentialsPath string
		scopeStr        string
		serviceFilter   string
		regionFilter    string
		statusFilter    string
		jsonOutput      bool
		verbose         bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--mode":
			if i+1 < len(args) {
				modeStr = strings.ToLower(args[i+1])
				i++
			}
		case arg == "--provider":
			if i+1 < len(args) {
				providerStr = strings.ToLower(args[i+1])
				i++
			}
		case arg == "--credentials" || arg == "--creds":
			if i+1 < len(args) {
				credentialsPath = args[i+1]
				i++
			}
		case arg == "--scope":
			if i+1 < len(args) {
				scopeStr = args[i+1]
				i++
			}
		case arg == "--service":
			if i+1 < len(args) {
				serviceFilter = strings.ToLower(args[i+1])
				i++
			}
		case arg == "--region":
			if i+1 < len(args) {
				regionFilter = strings.ToLower(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printCloudSecHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n\n")
		printCloudSecHelp()
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error finding assessment '%s': %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	// Load credentials if provided (in-memory only, never persisted)
	var creds cloudsec.Credentials
	if credentialsPath != "" {
		data, err := os.ReadFile(credentialsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read credentials file: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(data, &creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to parse credentials JSON: %v\n", err)
			return 1
		}
		defer creds.Scrub()
		if modeStr == "" {
			modeStr = "credentialed"
		}
	}

	// Determine assessment mode
	mode := cloudsec.ModeExternal
	if strings.EqualFold(modeStr, "credentialed") {
		mode = cloudsec.ModeCredentialed
	}

	if mode == cloudsec.ModeCredentialed && credentialsPath == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: Credentialed mode requires --credentials <path> pointing to scoped credentials JSON file\n")
		return 1
	}

	// Infer / Determine Provider
	var provider cloudsec.Provider
	switch strings.ToLower(providerStr) {
	case "aws":
		provider = cloudsec.ProviderAWS
	case "azure":
		provider = cloudsec.ProviderAzure
	case "gcp":
		provider = cloudsec.ProviderGCP
	default:
		if mode == cloudsec.ModeExternal {
			provider = cloudsec.ProviderMulti
		} else {
			if creds.AWSAccessKeyID != "" {
				provider = cloudsec.ProviderAWS
			} else if creds.AzureClientID != "" || creds.AzureTenantID != "" {
				provider = cloudsec.ProviderAzure
			} else if creds.GCPClientEmail != "" || creds.GCPProjectID != "" {
				provider = cloudsec.ProviderGCP
			} else if creds.Provider != "" {
				provider = creds.Provider
			} else {
				provider = cloudsec.ProviderAWS
			}
		}
	}
	creds.Provider = provider

	// Build DeclaredScope
	declaredScope := cloudsec.DeclaredScope{
		Provider: provider,
	}
	switch provider {
	case cloudsec.ProviderAWS:
		declaredScope.TargetAccountID = scopeStr
		if declaredScope.TargetAccountID == "" {
			declaredScope.TargetAccountID = creds.AWSAccountID
		}
	case cloudsec.ProviderAzure:
		declaredScope.TargetSubscription = scopeStr
		if declaredScope.TargetSubscription == "" {
			declaredScope.TargetSubscription = creds.AzureSubscriptionID
		}
	case cloudsec.ProviderGCP:
		declaredScope.TargetProjectID = scopeStr
		if declaredScope.TargetProjectID == "" {
			declaredScope.TargetProjectID = creds.GCPProjectID
		}
	}
	if serviceFilter != "" {
		declaredScope.Services = []string{serviceFilter}
	}
	if regionFilter != "" {
		declaredScope.Regions = []string{regionFilter}
	}

	// Build external targets
	var extTargets []cloudsec.ExternalTarget
	for _, t := range asm.Targets {
		u, err := url.Parse(t.TargetURL)
		if err == nil && u.Host != "" {
			host := u.Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			scheme := u.Scheme
			if scheme == "" {
				scheme = "https"
			}
			extTargets = append(extTargets, cloudsec.ExternalTarget{
				Hostname: host,
				URL:      t.TargetURL,
				Scheme:   scheme,
				Source:   "assessment_target",
			})
		}
	}

	var targetURLs []string
	for _, t := range asm.Targets {
		targetURLs = append(targetURLs, t.TargetURL)
	}
	scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)

	actx := &cloudsec.AssessmentContext{
		AssessmentID:    asm.ID,
		Mode:            mode,
		Provider:        provider,
		Scope:           declaredScope,
		Credentials:     creds,
		ExternalTargets: extTargets,
		IsAllowed:       scopeVal.IsAllowed,
		IsExcluded:      func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
	}

	// Check if existing results exist in database
	existingResults, _ := store.GetCloudSecResults(asm.ID, "", string(provider), serviceFilter, statusFilter)
	if !runExecution && !dryRun && len(existingResults) == 0 {
		dryRun = true
	}

	// 1. Dry Run Mode
	if dryRun {
		engine := cloudsec.NewEngine(cloudsec.DefaultConfig())
		plan, err := engine.Plan(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Plan error: %v\n", err)
			return 1
		}

		if jsonOutput {
			b, _ := json.MarshalIndent(plan, "", "  ")
			fmt.Println(string(b))
			return 0
		}

		fmt.Println("================================================================================")
		fmt.Printf("  FELIX :: REAL CLOUD SECURITY ASSESSMENT PLAN (DRY-RUN): %s\n", asm.Ref)
		fmt.Printf("  Assessment: %s | Mode: %s | Provider: %s\n", asm.Name, mode, provider)
		fmt.Printf("  Target Scope: %s\n", plan.TargetScope)
		if plan.VerifiedPrincipal != "" {
			fmt.Printf("  Verified Principal: %s\n", plan.VerifiedPrincipal)
		}
		fmt.Printf("  Planned Checks: %d | Ready: %d | Blocked: %d\n",
			len(plan.PlannedChecks), plan.ReadyChecks, plan.BlockedChecks)
		fmt.Println("================================================================================")

		fmt.Println("\n[+] SAFETY & ZERO-PERSISTENCE GUARANTEES:")
		fmt.Println("  - Zero Credential Persistence:  API keys, service account keys, and tokens are NEVER stored in DB or reports.")
		fmt.Println("  - Read-Only Assessment:         Auditing operations perform non-destructive inspect/read calls only.")
		fmt.Println("  - Fail-Closed Scope Validation: Authenticated principal must strictly match declared target scope.")
		fmt.Println("  - Centralized Scope Control:    All outbound calls and redirect targets are checked against approved targets.")
		fmt.Println("  - Evidence-First Verification:  Every finding is corroborated with observed facts and reproduction details.")

		fmt.Println("\n[+] PLANNED CLOUD SECURITY CHECKS:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CHECK ID\tPROVIDER\tSERVICE\tREAD-ONLY\tREQUIRED API / PERMISSION\tSTATUS")
		for _, c := range plan.PlannedChecks {
			reqAPI := c.RequiredAPI
			if reqAPI == "" {
				reqAPI = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\n",
				c.ID, c.Provider, c.Service, c.ReadOnly, reqAPI, c.Status)
		}
		_ = w.Flush()

		if mode == cloudsec.ModeExternal && len(extTargets) > 0 {
			fmt.Println("\n[+] EXTERNAL TARGETS IDENTIFIED:")
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "HOSTNAME\tSCHEME\tBASE URL\tSOURCE")
			for _, t := range extTargets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Hostname, t.Scheme, t.URL, t.Source)
			}
			_ = w.Flush()
		}

		fmt.Printf("\nTo execute active testing:\n  felix assessment cloudsec %s --run\n\n", asm.Ref)
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: no authorization record found for assessment %s\n", asm.Ref)
			return 1
		}
		valid, reason := asm.Authorization.IsCurrentlyValid(time.Now().UTC())
		if !valid {
			fmt.Fprintf(os.Stderr, "[-] Security refusal: authorization invalid: %s\n", reason)
			return 1
		}

		if mode == cloudsec.ModeExternal && len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: external mode requires at least one target URL in assessment %s\n", asm.Ref)
			return 1
		}

		execID := "exec-" + uuid.New().String()
		now := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    now,
			ConfigSnapshot: assessment.ScanConfigSnapshot{
				TimeoutSeconds: 15,
				Concurrency:    5,
				ScopeMode:      asm.ScopeMode,
				FelixVersion:   "2.0",
			},
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create execution record: %v\n", err)
			return 1
		}

		actx.ExecutionID = execID
		engine := cloudsec.NewEngine(cloudsec.DefaultConfig())

		fmt.Println("================================================================================")
		fmt.Printf("  EXECUTING CLOUD SECURITY AUDIT: %s (%s)\n", asm.Ref, asm.Name)
		fmt.Printf("  Mode: %s | Provider: %s\n", mode, provider)
		if declaredScope.TargetAccountID != "" {
			fmt.Printf("  Target Account ID: %s\n", declaredScope.TargetAccountID)
		} else if declaredScope.TargetSubscription != "" {
			fmt.Printf("  Target Subscription: %s\n", declaredScope.TargetSubscription)
		} else if declaredScope.TargetProjectID != "" {
			fmt.Printf("  Target Project ID: %s\n", declaredScope.TargetProjectID)
		}
		fmt.Println("================================================================================")

		startTime := time.Now()
		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			execRecord.ErrorMessage = err.Error()
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		duration := time.Since(startTime)
		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		execRecord.DurationMs = duration.Milliseconds()

		// Save results
		for i := range results {
			results[i].AssessmentID = asm.ID
			results[i].ExecutionID = execID
		}
		if err := store.SaveCloudSecResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save cloudsec results: %v\n", err)
		}

		// Save run record
		covJSON, _ := json.Marshal(summary.ServiceCoverageMap)
		runRec := &cloudsec.RunRecord{
			ID:                uuid.New().String(),
			AssessmentID:      asm.ID,
			ExecutionID:       execID,
			Mode:              mode,
			Provider:          provider,
			ScopeIdentifier:   summary.TargetScope,
			VerifiedPrincipal: summary.VerifiedPrincipal,
			SyntheticFixture:  summary.SyntheticFixture,
			TotalChecks:       summary.TotalChecks,
			ServicesAssessed:  summary.ServicesAssessed,
			VerifiedCount:     summary.VerifiedCount,
			CandidateCount:    summary.CandidateCount,
			ObservedCount:     summary.ObservedCount,
			CoverageJSON:      string(covJSON),
			CreatedAt:         completedAt,
		}
		if err := store.SaveCloudSecRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save cloudsec run record: %v\n", err)
		}

		// Save findings
		targetID := ""
		if len(asm.Targets) > 0 {
			targetID = asm.Targets[0].ID
		}
		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save findings: %v\n", err)
			}
		}

		_ = store.UpdateExecution(execRecord)

		fmt.Printf("\n[+] Assessment Complete in %v\n", duration.Round(time.Millisecond))
		fmt.Printf("    Total Checks: %d | Services Assessed: %d\n", summary.TotalChecks, summary.ServicesAssessed)
		fmt.Printf("    Verified Issues: %d | Candidates: %d | Observations: %d | Inconclusive: %d | Not Vulnerable: %d\n",
			summary.VerifiedCount, summary.CandidateCount, summary.ObservedCount, summary.InconclusiveCount, summary.NotVulnerableCount)
	}

	// 3. Reporting / Inspection Mode
	results, err := store.GetCloudSecResults(asm.ID, "", string(provider), serviceFilter, statusFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch cloudsec results: %v\n", err)
		return 1
	}

	summary, _ := store.GetCloudSecSummary(asm.ID, "")

	if jsonOutput {
		out := map[string]interface{}{
			"assessment_ref": asm.Ref,
			"mode":           mode,
			"provider":       provider,
			"summary":        summary,
			"results":        results,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	if summary != nil {
		fmt.Println("\n================================================================================")
		fmt.Printf("  FELIX :: REAL CLOUD SECURITY REPORT: %s\n", asm.Ref)
		modeDisplay := string(summary.Mode)
		if summary.SyntheticFixture {
			modeDisplay += " [SYNTHETIC FIXTURE SIMULATION]"
		}
		fmt.Printf("  Assessment: %s | Mode: %s | Provider: %s\n", asm.Name, modeDisplay, summary.Provider)
		fmt.Printf("  Target Scope: %s\n", summary.TargetScope)
		if summary.VerifiedPrincipal != "" {
			fmt.Printf("  Verified Principal: %s\n", summary.VerifiedPrincipal)
		}
		fmt.Printf("  Total Checks: %d | Services Assessed: %d\n", summary.TotalChecks, summary.ServicesAssessed)
		fmt.Printf("  Verified Issues: %d | Candidates: %d | Observations: %d | Inconclusive: %d | Not Vulnerable: %d\n",
			summary.VerifiedCount, summary.CandidateCount, summary.ObservedCount, summary.InconclusiveCount, summary.NotVulnerableCount)
		fmt.Println("================================================================================")

		if len(summary.ServiceCoverageMap) > 0 {
			fmt.Println("\n[+] SERVICE COVERAGE:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tSERVICE\tSTATUS\tCHECKS\tVERIFIED\tCANDIDATES\tOBSERVED\tINCONCLUSIVE\tNOT VULN")
			for svc, cov := range summary.ServiceCoverageMap {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
					cov.Provider, svc, cov.Status, cov.ChecksRun,
					cov.Verified, cov.Candidates, cov.Observations, cov.Inconclusive, cov.NotVulnerable)
			}
			_ = w.Flush()
		}
	}

	if len(results) > 0 {
		fmt.Println("\n[+] CLOUD SECURITY FINDINGS & RESULTS:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CHECK ID\tSERVICE\tRESOURCE\tSTATE\tSEVERITY\tCONFIDENCE\tEVIDENCE & DETAILS")
			for _, r := range results {
				detailsStr := r.EvidenceSummary
				if len(r.EvidenceDetails) > 0 {
					b, _ := json.Marshal(r.EvidenceDetails)
					detailsStr += " | Details: " + string(b)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.CheckID, r.Service, r.ResourceID, r.VerificationState, r.Severity, r.Confidence, detailsStr)
			}
		} else {
			fmt.Fprintln(w, "CHECK ID\tSERVICE\tRESOURCE\tSTATE\tSEVERITY\tEVIDENCE SUMMARY")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.CheckID, r.Service, r.ResourceID, r.VerificationState, r.Severity, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else if summary == nil || summary.TotalChecks == 0 {
		fmt.Println("\nNo cloud security results recorded.")
		fmt.Printf("To run a cloud security assessment:\n  felix assessment cloudsec %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

func printBusinessLogicHelp() {
	fmt.Println("Usage: felix assessment businesslogic <asm-ref> [options]")
	fmt.Println("\nEvaluate business logic security workflows, state transitions, replay, and invariants.")
	fmt.Println("\nAliases: bizlogic, logic")
	fmt.Println("\nOptions:")
	fmt.Println("  --run                 Execute active business logic assessment against authorized targets")
	fmt.Println("  --dry-run             Generate test plan and evaluate workflow prerequisites without state mutations")
	fmt.Println("  --workflow, -w        Filter by workflow ID (e.g. WF-ECOMMERCE-ORDER)")
	fmt.Println("  --category, -c        Filter by business logic category code (e.g. BL-01, BL-02)")
	fmt.Println("  --status, -s          Filter by verification state (VERIFIED, CANDIDATE, NOT_VULNERABLE, etc.)")
	fmt.Println("  --state-changing      Allow state-changing probes (default: safe read-only)")
	fmt.Println("  --json                Output results in JSON format")
	fmt.Println("  --verbose, -v         Display detailed findings, evidence observations, and remediation")
	fmt.Println("  --help, -h            Show this help text")
	fmt.Println("\nCategories:")
	fmt.Println("  BL-01  Workflow Circumvention (Skipped Steps)           [CWE-840, WSTG-BUSL-01]")
	fmt.Println("  BL-02  Unexpected State Transitions                     [CWE-372, WSTG-BUSL-02]")
	fmt.Println("  BL-03  State Manipulation & Parameter Integrity         [CWE-472, WSTG-BUSL-03]")
	fmt.Println("  BL-04  Unauthorized Workflow Access                     [CWE-285, WSTG-BUSL-04]")
	fmt.Println("  BL-05  Sensitive Business-Flow Abuse                    [CWE-799, WSTG-BUSL-05]")
	fmt.Println("  BL-06  Replay & Idempotency Flaws                       [CWE-294, WSTG-BUSL-06]")
	fmt.Println("  BL-07  Privilege & State Inconsistency                  [CWE-269, WSTG-BUSL-07]")
	fmt.Println("  BL-08  Business Data Validation & Invariants            [CWE-20,  WSTG-BUSL-08]")
	fmt.Println("\nExamples:")
	fmt.Println("  felix assessment businesslogic <asm-ref> --dry-run")
	fmt.Println("  felix assessment businesslogic <asm-ref> --run")
	fmt.Println("  felix assessment businesslogic <asm-ref> --category BL-01 --verbose")
	fmt.Println("  felix assessment businesslogic <asm-ref> --json")
}

func runAssessmentBusinessLogic(args []string) int {
	var (
		assessmentRef  string
		runExecution   bool
		dryRun         bool
		workflowFilter string
		categoryFilter string
		statusFilter   string
		stateChanging  bool
		policyPath     string
		jsonOutput     bool
		verbose        bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--run":
			runExecution = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--workflow" || arg == "-w":
			if i+1 < len(args) {
				workflowFilter = args[i+1]
				i++
			}
		case arg == "--category" || arg == "-c":
			if i+1 < len(args) {
				categoryFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--status" || arg == "-s":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--state-changing":
			stateChanging = true
		case arg == "--policy" || arg == "--identities":
			if i+1 < len(args) {
				policyPath = args[i+1]
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printBusinessLogicHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: assessment ID or Ref is required\n\n")
		printBusinessLogicHelp()
		return 2
	}

	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database error: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error finding assessment '%s': %v\n", assessmentRef, err)
		return 1
	}
	asm.Targets, _ = store.GetTargets(asm.ID)
	asm.Authorization, _ = store.GetAuthorization(asm.ID)
	asm.Exclusions, _ = store.GetExclusions(asm.ID)
	asm.ScopeRules, _ = store.GetScopeRules(asm.ID)

	targetBase := "http://localhost"
	var targetURLs []string
	if len(asm.Targets) > 0 {
		targetBase = strings.TrimRight(asm.Targets[0].TargetURL, "/")
		for _, t := range asm.Targets {
			targetURLs = append(targetURLs, t.TargetURL)
		}
	}

	// Load inventory endpoints and auth surfaces
	assets, _, _ := store.GetInventory(asm.ID, "", "", true)
	authInv, _ := store.GetAuthInventory(asm.ID, "", "")

	var discoveredEndpoints []businesslogic.DiscoveredEndpoint
	seenEndpoints := make(map[string]bool)

	for _, a := range assets {
		if a.Type == "ENDPOINT" || a.Type == "endpoint" {
			method := "GET"
			if m, ok := a.Metadata["method"].(string); ok && m != "" {
				method = strings.ToUpper(m)
			}
			path := a.DisplayName
			if p, ok := a.Metadata["path"].(string); ok && p != "" {
				path = p
			} else if a.CanonicalID != "" {
				path = a.CanonicalID
			}
			if u, err := url.Parse(path); err == nil && u.Path != "" {
				path = u.Path
			}
			epType := ""
			if t, ok := a.Metadata["type"].(string); ok && t != "" {
				epType = t
			}
			key := method + " " + path
			if !seenEndpoints[key] {
				seenEndpoints[key] = true
				discoveredEndpoints = append(discoveredEndpoints, businesslogic.DiscoveredEndpoint{
					Method: method,
					Path:   path,
					Type:   epType,
				})
			}
		}
	}

	if authInv != nil {
		for _, surf := range authInv.Surfaces {
			path := surf.Identifier
			if u, err := url.Parse(path); err == nil && u.Path != "" {
				path = u.Path
			}
			method := "GET"
			if m, ok := surf.Metadata["method"].(string); ok && m != "" {
				method = strings.ToUpper(m)
			}
			epType := ""
			if t, ok := surf.Metadata["type"].(string); ok && t != "" {
				epType = t
			}
			key := method + " " + path
			if !seenEndpoints[key] {
				seenEndpoints[key] = true
				discoveredEndpoints = append(discoveredEndpoints, businesslogic.DiscoveredEndpoint{
					Method: method,
					Path:   path,
					Type:   epType,
				})
			}
		}
	}

	var testIdentities []businesslogic.TestIdentity
	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err == nil {
			_ = json.Unmarshal(data, &testIdentities)
		} else {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to read policy/identities file '%s': %v\n", policyPath, err)
		}
	}

	scopeVal := assessment.NewScopeValidator(asm.ScopeMode, targetURLs, asm.ScopeRules, asm.Exclusions)

	actx := &businesslogic.AssessmentContext{
		AssessmentID:  asm.ID,
		BaseURL:       targetBase,
		Endpoints:     discoveredEndpoints,
		Identities:    testIdentities,
		IsAllowed:     scopeVal.IsAllowed,
		IsExcluded:    func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		RequestBudget: 50,
		DryRun:        dryRun,
	}

	// Check if existing results exist in database
	existingResults, _ := store.GetBusinessLogicResults(asm.ID, "", categoryFilter, statusFilter)
	if !runExecution && !dryRun && len(existingResults) == 0 {
		dryRun = true
	}

	// 1. Dry Run Mode
	if dryRun {
		cfg := businesslogic.DefaultConfig()
		cfg.AllowStateChanging = stateChanging
		engine := businesslogic.NewEngine(nil, cfg)

		plan, err := engine.Plan(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Dry run planning failed: %v\n", err)
			return 1
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(plan)
			return 0
		}

		fmt.Println("================================================================================")
		fmt.Printf("FELIX BUSINESS LOGIC SECURITY ENGINE - DRY RUN TEST PLAN\n")
		fmt.Println("================================================================================")
		fmt.Printf("Assessment:     %s (%s)\n", asm.Name, asm.Ref)
		fmt.Printf("Target Base:    %s\n", targetBase)
		fmt.Printf("Workflows:      %d modeled\n", plan.TotalWorkflows)
		fmt.Printf("Total Checks:   %d planned (%d ready, %d blocked)\n", plan.TotalPlannedChecks, plan.ReadyChecks, plan.BlockedChecks)
		if stateChanging {
			fmt.Println("State Change:   ENABLED (--state-changing active)")
		} else {
			fmt.Println("State Change:   DISABLED (Safe read-only mode)")
		}
		fmt.Println("--------------------------------------------------------------------------------")

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CHECK ID\tCATEGORY\tWORKFLOW\tSTATUS\tPREREQUISITES / OBJECTIVE")
		for _, pc := range plan.PlannedChecks {
			if workflowFilter != "" && pc.WorkflowID != workflowFilter {
				continue
			}
			if categoryFilter != "" && string(pc.Category) != categoryFilter {
				continue
			}
			prereqStr := strings.Join(pc.Preconditions, ", ")
			if pc.BlockedReason != "" {
				prereqStr = fmt.Sprintf("BLOCKED: %s", pc.BlockedReason)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", pc.ID, pc.Category, pc.WorkflowID, pc.Status, prereqStr)
		}
		_ = w.Flush()

		fmt.Printf("\nTo execute active business logic testing:\n  felix assessment businesslogic %s --run\n\n", asm.Ref)
		return 0
	}

	// 2. Execution Mode
	if runExecution {
		if asm.Authorization == nil {
			fmt.Fprintf(os.Stderr, "[-] Assessment %s is NOT authorized. Client authorization required before running active testing.\n", asm.Ref)
			return 1
		}
		if len(asm.Targets) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Error: assessment requires at least one target URL in %s\n", asm.Ref)
			return 1
		}

		execID := uuid.New().String()
		startedAt := time.Now().UTC()
		execRecord := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asm.ID,
			Status:       assessment.StatusRunning,
			StartedAt:    startedAt,
		}
		if err := store.CreateExecution(execRecord); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to record execution: %v\n", err)
		}

		actx.ExecutionID = execID
		cfg := businesslogic.DefaultConfig()
		cfg.AllowStateChanging = stateChanging
		engine := businesslogic.NewEngine(nil, cfg)

		fmt.Println("================================================================================")
		fmt.Printf("FELIX BUSINESS LOGIC SECURITY ENGINE - ACTIVE EVALUATION\n")
		fmt.Println("================================================================================")
		fmt.Printf("Assessment:     %s (%s)\n", asm.Name, asm.Ref)
		fmt.Printf("Target Base:    %s\n", targetBase)
		fmt.Printf("Execution ID:   %s\n", execID)
		if stateChanging {
			fmt.Println("Mode:           STATE-CHANGING ENABLED")
		} else {
			fmt.Println("Mode:           SAFE READ-ONLY (State mutations blocked by policy)")
		}
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("[*] Modeling business workflows and evaluating state boundaries...")

		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Assessment failed: %v\n", err)
			execRecord.Status = assessment.StatusFailed
			now := time.Now().UTC()
			execRecord.CompletedAt = &now
			_ = store.UpdateExecution(execRecord)
			return 1
		}

		completedAt := time.Now().UTC()
		execRecord.Status = assessment.StatusCompleted
		execRecord.CompletedAt = &completedAt
		_ = store.UpdateExecution(execRecord)

		for i := range results {
			results[i].ExecutionID = execID
		}
		if err := store.SaveBusinessLogicResults(results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save business logic results: %v\n", err)
		}

		covJSON, _ := json.Marshal(summary.CategoryCoverageMap)
		runRec := &businesslogic.RunRecord{
			ID:                 uuid.New().String(),
			AssessmentID:       asm.ID,
			ExecutionID:        execID,
			TargetURL:          targetBase,
			TotalChecks:        summary.TotalChecks,
			CategoriesAssessed: summary.CategoriesAssessed,
			WorkflowsModeled:   summary.WorkflowsModeled,
			VerifiedCount:      summary.VerifiedCount,
			CandidateCount:     summary.CandidateCount,
			ObservedCount:      summary.ObservedCount,
			InconclusiveCount:  summary.InconclusiveCount,
			BlockedCount:       summary.BlockedCount,
			NotVulnerableCount: summary.NotVulnerableCount,
			SyntheticFixture:   summary.SyntheticFixture,
			CoverageJSON:       string(covJSON),
			CreatedAt:          completedAt,
		}
		if err := store.SaveBusinessLogicRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save business logic run record: %v\n", err)
		}

		// Save findings
		targetID := ""
		if len(asm.Targets) > 0 {
			targetID = asm.Targets[0].ID
		}
		var asmFindings []assessment.AssessmentFinding
		for _, f := range findings {
			asmFindings = append(asmFindings, assessment.ToAssessmentFinding(asm.ID, execID, targetID, f))
		}
		if len(asmFindings) > 0 {
			if err := store.SaveFindings(asmFindings); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Warning: failed to save findings: %v\n", err)
			}
		}

		fmt.Printf("[+] Assessment completed: %d checks run across %d workflows\n", summary.TotalChecks, summary.WorkflowsModeled)
		fmt.Printf("    Verified:       %d\n", summary.VerifiedCount)
		fmt.Printf("    Candidates:     %d\n", summary.CandidateCount)
		fmt.Printf("    Observations:   %d\n", summary.ObservedCount)
		fmt.Printf("    Not Vulnerable: %d\n", summary.NotVulnerableCount)
		fmt.Printf("    Blocked/Safety: %d\n", summary.BlockedCount)
		fmt.Printf("    Inconclusive:   %d\n", summary.InconclusiveCount)
	}

	// 3. Reporting / Inspection Mode
	results, err := store.GetBusinessLogicResults(asm.ID, "", categoryFilter, statusFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch business logic results: %v\n", err)
		return 1
	}

	summary, _ := store.GetBusinessLogicSummary(asm.ID, "")

	if jsonOutput {
		out := map[string]interface{}{
			"assessment_ref": asm.Ref,
			"target_url":     targetBase,
			"summary":        summary,
			"results":        results,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	if summary != nil && summary.TotalChecks > 0 {
		fmt.Println("\n================================================================================")
		fmt.Printf("BUSINESS LOGIC SECURITY ASSESSMENT SUMMARY: %s (%s)\n", asm.Name, asm.Ref)
		fmt.Println("================================================================================")
		fmt.Printf("Target Base:        %s\n", targetBase)
		fmt.Printf("Total Checks:       %d\n", summary.TotalChecks)
		fmt.Printf("Categories Tested:  %d of 8\n", summary.CategoriesAssessed)
		fmt.Printf("Workflows Modeled:  %d\n", summary.WorkflowsModeled)
		fmt.Printf("Verified Issues:    %d\n", summary.VerifiedCount)
		fmt.Printf("Candidates:         %d\n", summary.CandidateCount)
		fmt.Printf("Observations:       %d\n", summary.ObservedCount)
		fmt.Printf("Not Vulnerable:     %d\n", summary.NotVulnerableCount)
		fmt.Printf("Blocked (Safety):   %d\n", summary.BlockedCount)
		fmt.Printf("Inconclusive:       %d\n", summary.InconclusiveCount)
		if summary.SyntheticFixture {
			fmt.Printf("Fixture Status:     SYNTHETIC FIXTURE SIMULATION\n")
		}
		fmt.Println("--------------------------------------------------------------------------------")

		fmt.Println("\nCATEGORY COVERAGE BREAKDOWN:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "CATEGORY\tNAME\tSTATUS\tCHECKS\tVERIFIED\tCANDIDATES\tNOT VULN\tBLOCKED")
		for _, cat := range businesslogic.AllCategories() {
			catKey := string(cat)
			cov, ok := summary.CategoryCoverageMap[catKey]
			if !ok {
				meta := businesslogic.CategoryMetadata[cat]
				cov = businesslogic.CategoryCoverage{
					Category: cat,
					Code:     meta.Code,
					Name:     meta.Name,
					Status:   businesslogic.CoverageUntested,
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
				cov.Code, cov.Name, cov.Status, cov.ChecksRun, cov.Verified, cov.Candidates, cov.NotVulnerable, cov.Blocked)
		}
		_ = w.Flush()
	}

	if len(results) > 0 {
		fmt.Println("\nRESULTS:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if verbose {
			fmt.Fprintln(w, "CHECK ID\tCATEGORY\tWORKFLOW\tSTATE\tSEVERITY\tCONFIDENCE\tEVIDENCE & DETAILS")
			for _, r := range results {
				if workflowFilter != "" && r.WorkflowID != workflowFilter {
					continue
				}
				detailsStr := r.EvidenceSummary
				if len(r.EvidenceDetails) > 0 {
					b, _ := json.Marshal(r.EvidenceDetails)
					detailsStr += " | Details: " + string(b)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.CheckID, r.Category, r.WorkflowName, r.VerificationState, r.Severity, r.Confidence, detailsStr)
			}
		} else {
			fmt.Fprintln(w, "CHECK ID\tCATEGORY\tWORKFLOW\tSTATE\tSEVERITY\tEVIDENCE SUMMARY")
			for _, r := range results {
				if workflowFilter != "" && r.WorkflowID != workflowFilter {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.CheckID, r.Category, r.WorkflowName, r.VerificationState, r.Severity, r.EvidenceSummary)
			}
		}
		_ = w.Flush()
	} else if summary == nil || summary.TotalChecks == 0 {
		fmt.Println("\nNo business logic security results recorded.")
		fmt.Printf("To run a business logic security assessment:\n  felix assessment businesslogic %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}

func runAssessmentCorrelate(args []string) int {
	var (
		assessmentRef string
		executionID   string
		statusFilter  string
		riskFilter    string
		ruleFilter    string
		runFlag       bool
		jsonOutput    bool
		verbose       bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--run":
			runFlag = true
		case "--execution", "--exec":
			if i+1 < len(args) {
				executionID = args[i+1]
				i++
			}
		case "--status":
			if i+1 < len(args) {
				statusFilter = strings.ToUpper(args[i+1])
				i++
			}
		case "--risk":
			if i+1 < len(args) {
				riskFilter = strings.ToUpper(args[i+1])
				i++
			}
		case "--rule":
			if i+1 < len(args) {
				ruleFilter = strings.ToUpper(args[i+1])
				i++
			}
		case "--json":
			jsonOutput = true
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h":
			fmt.Println("Usage: felix assessment correlate <assessment-id> [flags]")
			fmt.Println("\nFlags:")
			fmt.Println("  --run              Execute correlation analysis across recorded findings")
			fmt.Println("  --execution <id>   Scope to specific execution ID")
			fmt.Println("  --status <state>   Filter paths by status (VERIFIED, CANDIDATE, INCONCLUSIVE, OBSERVED)")
			fmt.Println("  --risk <level>     Filter paths by minimum risk level (CRITICAL, HIGH, MEDIUM, LOW)")
			fmt.Println("  --rule <code>      Filter paths by rule code (COR-01 to COR-10)")
			fmt.Println("  --json             Output results as formatted JSON")
			fmt.Println("  --verbose          Display full multi-step node chains and security story explanations")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && assessmentRef == "" {
				assessmentRef = arg
			}
		}
	}

	if assessmentRef == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: assessment ID or reference is required")
		fmt.Fprintln(os.Stderr, "Usage: felix assessment correlate <assessment-id> [flags]")
		return 1
	}

	store, err := assessment.NewSQLiteStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Database initialization failed: %v\n", err)
		return 1
	}
	defer store.Close()

	asm, err := store.GetAssessment(assessmentRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment %q not found: %v\n", assessmentRef, err)
		return 1
	}

	// 1. Run Mode
	if runFlag {
		fmt.Println("================================================================================")
		fmt.Printf("FELIX CORRELATION & ATTACK PATH ENGINE - ANALYSIS RUN\n")
		fmt.Println("================================================================================")
		fmt.Printf("Assessment:     %s (%s)\n", asm.Name, asm.Ref)
		if executionID != "" {
			fmt.Printf("Execution ID:   %s\n", executionID)
		}
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("[*] Fetching recorded assessment findings for cross-finding correlation...")

		rawFindings, err := store.GetFindings(asm.ID, executionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to fetch findings: %v\n", err)
			return 1
		}

		if len(rawFindings) == 0 {
			fmt.Printf("[-] No findings recorded for assessment %s. Run an assessment scan first.\n", asm.Ref)
			return 1
		}

		var reportFindings []report.Finding
		for _, f := range rawFindings {
			rf := report.Finding{
				ID:              f.OriginalFindingID,
				Title:           f.Title,
				Category:        f.Category,
				Severity:        f.Severity,
				Confidence:      f.Confidence,
				Score:           f.Score,
				Target:          f.TargetURL,
				Endpoint:        f.Endpoint,
				Method:          f.Method,
				EvidenceDetails: f.EvidenceDetails,
				Verification:    f.VerificationRecord,
				Remediation:     f.Remediation,
			}
			if rf.ID == "" {
				rf.ID = f.ID
			}
			reportFindings = append(reportFindings, rf)
		}

		cfg := correlation.DefaultConfig()
		engine := correlation.NewEngine(cfg)

		fmt.Printf("[*] Evaluating correlation rules COR-01 through COR-10 across %d findings...\n", len(reportFindings))
		summary, paths, relationships, err := engine.Correlate(context.Background(), reportFindings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Correlation engine error: %v\n", err)
			return 1
		}

		execID := executionID
		if execID == "" {
			execID = uuid.New().String()
			now := time.Now().UTC()
			execRec := &assessment.AssessmentExecution{
				ID:           execID,
				AssessmentID: asm.ID,
				Status:       assessment.StatusCompleted,
				StartedAt:    now,
				CompletedAt:  &now,
				FindingCount: len(rawFindings),
			}
			_ = store.CreateExecution(execRec)
		}

		covJSON, _ := json.Marshal(summary)
		runRec := &correlation.RunRecord{
			ID:                     uuid.New().String(),
			AssessmentID:           asm.ID,
			ExecutionID:            execID,
			TotalFindings:          summary.TotalFindings,
			CandidateRelationships: summary.CandidateRelationships,
			CandidatePaths:         summary.CandidatePaths,
			VerifiedPaths:          summary.VerifiedPaths,
			HighestRisk:            summary.HighestRiskLevel,
			CoverageJSON:           string(covJSON),
			SyntheticFixture:       summary.SyntheticFixture,
			CreatedAt:              time.Now().UTC(),
		}
		if err := store.SaveCorrelationRun(runRec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save correlation run: %v\n", err)
		}

		if err := store.SaveAttackPaths(asm.ID, execID, paths); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: failed to save attack paths: %v\n", err)
		}

		fmt.Printf("[+] Correlation analysis completed:\n")
		fmt.Printf("    Evaluated Findings:        %d\n", summary.EvaluatedFindings)
		fmt.Printf("    Candidate Relationships:   %d\n", summary.CandidateRelationships)
		fmt.Printf("    Confirmed Relationships:   %d\n", summary.ConfirmedRelationships)
		fmt.Printf("    Candidate Attack Paths:    %d\n", summary.CandidatePaths)
		fmt.Printf("    Verified Attack Paths:     %d\n", summary.VerifiedPaths)
		fmt.Printf("    Inconclusive Paths:        %d\n", summary.InconclusivePaths)
		fmt.Printf("    Highest Combined Risk:     %s (%d/100)\n", summary.HighestRiskLevel, summary.HighestRiskScore)
		if summary.LimitsReached {
			fmt.Printf("    [!] Limits Reached:        %s\n", summary.TruncationReason)
		}
		_ = relationships
	}

	// 2. Inspection / Output Mode
	paths, err := store.GetAttackPaths(asm.ID, executionID, statusFilter, riskFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to fetch attack paths: %v\n", err)
		return 1
	}

	if ruleFilter != "" {
		var filtered []correlation.AttackPath
		for _, p := range paths {
			hasRule := false
			for _, e := range p.Edges {
				if strings.EqualFold(string(e.RuleCode), ruleFilter) {
					hasRule = true
					break
				}
			}
			if hasRule {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	summary, _ := store.GetCorrelationSummary(asm.ID, executionID)

	if jsonOutput {
		out := map[string]interface{}{
			"assessment_ref": asm.Ref,
			"summary":        summary,
			"attack_paths":   paths,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	if summary != nil && (summary.CandidatePaths > 0 || summary.VerifiedPaths > 0 || len(paths) > 0) {
		fmt.Println("\n================================================================================")
		fmt.Printf("CORRELATION & ATTACK PATH ANALYSIS SUMMARY: %s (%s)\n", asm.Name, asm.Ref)
		fmt.Println("================================================================================")
		fmt.Printf("Total Findings:         %d\n", summary.TotalFindings)
		fmt.Printf("Candidate Relationships: %d\n", summary.CandidateRelationships)
		fmt.Printf("Confirmed Relationships: %d\n", summary.ConfirmedRelationships)
		fmt.Printf("Candidate Paths:        %d\n", summary.CandidatePaths)
		fmt.Printf("Verified Paths:         %d\n", summary.VerifiedPaths)
		fmt.Printf("Inconclusive Paths:     %d\n", summary.InconclusivePaths)
		fmt.Printf("Highest Combined Risk:  %s (%d/100)\n", summary.HighestRiskLevel, summary.HighestRiskScore)
		if len(summary.AffectedAssets) > 0 {
			fmt.Printf("Affected Assets:        %s\n", strings.Join(summary.AffectedAssets, ", "))
		}
		if summary.LimitsReached {
			fmt.Printf("Pruning / Limits:       %s\n", summary.TruncationReason)
		}
		fmt.Println("--------------------------------------------------------------------------------")

		fmt.Println("\nCORRELATION RULE COVERAGE:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "RULE\tNAME\tEDGE TYPE\tRELATIONSHIPS\tPATHS GENERATED")
		for _, code := range correlation.AllRules() {
			meta := correlation.RuleCatalog[code]
			st := summary.RuleStats[string(code)]
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n",
				code, meta.Name, meta.EdgeType, st.RelationshipsGenerated, st.PathsGenerated)
		}
		_ = w.Flush()
	}

	if len(paths) > 0 {
		fmt.Println("\nATTACK PATHS:")
		if verbose {
			for i, p := range paths {
				fmt.Printf("\n--- [Path %d: %s] ------------------------------------\n", i+1, p.ID)
				fmt.Printf("Title:          %s\n", p.Title)
				fmt.Printf("Status:         %s | Confidence: %s\n", p.Status, p.Confidence)
				fmt.Printf("Combined Risk:  %s (%d/100)\n", p.CombinedRiskLevel, p.CombinedRiskScore)
				fmt.Printf("Target Asset:   %s\n", p.TargetAsset)
				fmt.Printf("Primary Flaw:   %s\n", p.PrimaryWeakness)
				fmt.Printf("Terminal Impact:%s\n", p.TerminalImpact)
				fmt.Printf("Risk Rationale: %s\n", p.RiskRationale)

				fmt.Println("\n  PATH CHAIN:")
				for stepIdx, n := range p.Nodes {
					fmt.Printf("    [%d] %s (%s) - %s [%s]\n",
						stepIdx+1, n.ID, n.Category, n.Title, n.Endpoint)
					if stepIdx < len(p.Edges) {
						e := p.Edges[stepIdx]
						fmt.Printf("        ↳ %s via %s (%s, %s)\n",
							e.Type, e.RuleCode, e.ValidationStatus, e.Confidence)
					}
				}

				fmt.Println("\n  SECURITY STORY & EXPLANATION:")
				fmt.Printf("    1. Primary Weakness:         %s\n", p.PrimaryWeakness)
				if p.EntryPoint != "" {
					fmt.Printf("    2. Attack Reachability:       Entry point accessible via %s\n", p.EntryPoint)
				}
				if len(p.Assumptions) > 0 {
					fmt.Printf("    3. Preconditions/Assumptions: %s\n", strings.Join(p.Assumptions, "; "))
				}
				fmt.Printf("    4. Technical Consequence:     %s\n", p.TerminalImpact)
				if p.SecurityStory.Impact != "" {
					fmt.Printf("    5. Business Consequence:      %s\n", p.SecurityStory.Impact)
				}
				if len(p.SecurityStory.Evidence) > 0 {
					fmt.Printf("    6. Supporting Evidence:       %s\n", strings.Join(p.SecurityStory.Evidence, "; "))
				}
				if len(p.MissingEvidence) > 0 {
					fmt.Printf("    7. Missing Evidence / Gaps:   %s\n", strings.Join(p.MissingEvidence, "; "))
				}
				if p.SecurityStory.InvestigateFirst != "" {
					fmt.Printf("    8. Investigate First:         %s\n", p.SecurityStory.InvestigateFirst)
				}
				if p.Remediation != "" {
					fmt.Printf("    9. Choke Point Remediation:   %s\n", p.Remediation)
				}
				fmt.Println()
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "STATUS\tRISK\tSCORE\tSTEPS\tTITLE\tTARGET ASSET")
			for _, p := range paths {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
					p.Status, p.CombinedRiskLevel, p.CombinedRiskScore, len(p.Nodes), p.Title, p.TargetAsset)
			}
			_ = w.Flush()
			fmt.Printf("\nUse --verbose to see full path chains, supporting evidence, and security stories.\n")
		}
	} else if summary == nil || (summary.CandidatePaths == 0 && summary.VerifiedPaths == 0) {
		fmt.Println("\nNo attack paths or correlations recorded.")
		fmt.Printf("To run correlation analysis across findings:\n  felix assessment correlate %s --run\n", asm.Ref)
	}

	fmt.Println()
	return 0
}
