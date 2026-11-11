package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"felix/pkg/intelligence"
)

// CapabilityInfo represents operational and maturity metadata for a Felix engine module.
type CapabilityInfo struct {
	Command     string   `json:"command"`
	Engine      string   `json:"engine"`
	Maturity    string   `json:"maturity"`
	LicenseTier string   `json:"license_tier"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
}

// getAllCapabilities returns the comprehensive list of Felix 1.0 assessment capabilities and engines.
func getAllCapabilities() []CapabilityInfo {
	return []CapabilityInfo{
		{
			Command:     "assess",
			Engine:      "Unified Orchestrator",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "End-to-end multi-module assessment workflow across profiles (quick, standard, full, api, custom)",
			Categories:  []string{"orchestration", "workflow", "reporting"},
		},
		{
			Command:     "recon",
			Engine:      "Attack-Surface Intelligence",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Passive & active attack surface discovery, endpoints, forms, parameters, and TLS SAN hosts",
			Categories:  []string{"discovery", "crawler", "assets"},
		},
		{
			Command:     "scan",
			Engine:      "Web Vulnerability Scanner",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Automated web application crawl, injection testing, and multi-vector exposure audit",
			Categories:  []string{"web", "sqli", "xss", "ssrf"},
		},
		{
			Command:     "web",
			Engine:      "Web Vulnerability Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "OWASP Top 10 vulnerabilities (SQLi, XSS, SSRF, Path Traversal, Open Redirect, Command Injection)",
			Categories:  []string{"owasp_top10", "injection", "broken_access"},
		},
		{
			Command:     "api",
			Engine:      "API Security Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "REST/GraphQL API discovery, OpenAPI spec validation, method fuzzing, and content tampering",
			Categories:  []string{"api", "graphql", "rest", "schema"},
		},
		{
			Command:     "auth",
			Engine:      "Authentication Security Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Authentication surface analysis, weak credentials, token lifecycle, and session boundary audits",
			Categories:  []string{"auth", "tokens", "session"},
		},
		{
			Command:     "authz",
			Engine:      "Authorization Matrix Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "PROFESSIONAL",
			Description: "Multi-role RBAC enforcement, horizontal & vertical privilege escalation probing",
			Categories:  []string{"authz", "rbac", "privilege_escalation"},
		},
		{
			Command:     "bola",
			Engine:      "BOLA / IDOR Probing Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "PROFESSIONAL",
			Description: "Broken Object Level Authorization (IDOR) detection across tenant object boundaries",
			Categories:  []string{"bola", "idor", "api_top10"},
		},
		{
			Command:     "bfla",
			Engine:      "BFLA Probing Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "PROFESSIONAL",
			Description: "Broken Function Level Authorization audit, administrative route bypass testing",
			Categories:  []string{"bfla", "privilege_escalation", "admin_bypass"},
		},
		{
			Command:     "bopla",
			Engine:      "BOPLA / Mass Assignment Engine",
			Maturity:    "LAB-TESTED",
			LicenseTier: "PROFESSIONAL",
			Description: "Read-only excessive data exposure checks; state-changing mass-assignment remains LAB-TESTED and gated to verified isolated synthetic fixtures (--allow-state-changing --synthetic-fixture)",
			Categories:  []string{"bopla", "excessive_exposure", "mass_assignment", "property_tampering"},
		},
		{
			Command:     "graphql",
			Engine:      "GraphQL Inspection Engine",
			Maturity:    "LAB-TESTED",
			LicenseTier: "COMMUNITY",
			Description: "GraphQL schema inspection and introspection testing (in-memory mock validated only; excluded from commercial scope)",
			Categories:  []string{"graphql", "schema", "api"},
		},
		{
			Command:     "secrets",
			Engine:      "Entropy & Secret Detector",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "High-entropy secrets, cloud tokens, private keys, and credential leakage detection with redaction",
			Categories:  []string{"secrets", "credentials", "entropy"},
		},
		{
			Command:     "cloud",
			Engine:      "Cloud Security Engine",
			Maturity:    "MOCK-VALIDATED",
			LicenseTier: "ENTERPRISE",
			Description: "Cloud bucket and storage syntax auditor (protocol mocks only; unvalidated against live cloud provider infrastructure)",
			Categories:  []string{"cloud", "s3", "blob", "storage"},
		},
		{
			Command:     "mobile",
			Engine:      "Mobile APK Audit Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "ENTERPRISE",
			Description: "Android APK static analysis, manifest security, DEX bytecode secret extraction, exported components",
			Categories:  []string{"mobile", "android", "apk"},
		},
		{
			Command:     "cve",
			Engine:      "CVE & NVD Knowledge Base",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Embedded SQLite CVE database, CPE dictionary lookup, and semantic version range matching",
			Categories:  []string{"cve", "nvd", "semver"},
		},
		{
			Command:     "oast",
			Engine:      "Out-of-Band Testing (OAST)",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "PROFESSIONAL",
			Description: "Cryptographic OAST interaction tokens, DNS/HTTP callback listener and finding correlator",
			Categories:  []string{"oast", "callback", "blind_vuln"},
		},
		{
			Command:     "session",
			Engine:      "Session Security Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Cookie security flags (Secure, HttpOnly, SameSite), session fixation, and token entropy",
			Categories:  []string{"session", "cookies", "tokens"},
		},
		{
			Command:     "businesslogic",
			Engine:      "Business Logic Engine",
			Maturity:    "LAB-TESTED",
			LicenseTier: "PROFESSIONAL",
			Description: "State machine bypass, price manipulation, race conditions, and workflow subversion",
			Categories:  []string{"logic", "workflows", "race_conditions"},
		},
		{
			Command:     "workflow",
			Engine:      "Workflow Integrity Engine",
			Maturity:    "LAB-TESTED",
			LicenseTier: "PROFESSIONAL",
			Description: "Multi-step transaction integrity and state machine order validation",
			Categories:  []string{"workflow", "transaction_integrity"},
		},
		{
			Command:     "report",
			Engine:      "Zero-Network Reporter",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "COMMUNITY",
			Description: "Zero-network offline reporting: interactive HTML executive reports, JSON, and SARIF 2.1.0",
			Categories:  []string{"reporting", "sarif", "html", "json"},
		},
		{
			Command:     "compliance",
			Engine:      "Compliance Mapping Engine",
			Maturity:    "PRODUCTION-GRADE",
			LicenseTier: "ENTERPRISE",
			Description: "Regulatory frameworks: OWASP Top 10, PCI-DSS 4.0, SOC 2, ISO 27001, HIPAA, and gap analysis",
			Categories:  []string{"compliance", "pci", "soc2", "iso27001"},
		},
	}
}

// runCapabilities executes the "felix capabilities" subcommand.
func runCapabilities(args []string) int {
	var (
		jsonOutput      bool
		tierFilter      string
		maturityFilter  string
		showCatalogue   bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			jsonOutput = true
		case arg == "--tier":
			if i+1 < len(args) {
				tierFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--maturity":
			if i+1 < len(args) {
				maturityFilter = strings.ToUpper(args[i+1])
				i++
			}
		case arg == "--catalogue" || arg == "--vulns" || arg == "--catalog":
			showCatalogue = true
		case arg == "--help" || arg == "-h":
			printCapabilitiesHelp()
			return 0
		}
	}

	if showCatalogue {
		cat := intelligence.GetMasterCatalogue()
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(cat)
			return 0
		}
		fmt.Print(banner)
		fmt.Println("FELIX 1.0 COMPREHENSIVE VULNERABILITY CATALOGUE")
		fmt.Println("=========================================================================================")
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tCATEGORY\tOWASP\tCWE\tSEV\tSTATUS\tSTRATEGY")
		fmt.Fprintln(w, "--\t----\t--------\t-----\t---\t---\t------\t--------")
		for _, v := range cat {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				v.ID, truncateStr(v.Name, 30), truncateStr(v.Category, 24), v.OWASP, v.CWE, v.Severity, v.Status, v.DetectionStrategy)
		}
		_ = w.Flush()
		fmt.Println("=========================================================================================")
		fmt.Printf("Total Registered Vulnerability Classes: %d\n\n", len(cat))
		return 0
	}

	caps := getAllCapabilities()
	var filtered []CapabilityInfo
	for _, c := range caps {
		if tierFilter != "" && !strings.EqualFold(c.LicenseTier, tierFilter) {
			continue
		}
		if maturityFilter != "" && !strings.Contains(strings.ToUpper(c.Maturity), maturityFilter) {
			continue
		}
		filtered = append(filtered, c)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(filtered); err != nil {
			fmt.Fprintf(os.Stderr, "[-] JSON encoding error: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 CAPABILITIES & ENGINE REGISTRY")
	fmt.Println("=========================================================================================")

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "COMMAND\tENGINE\tMATURITY\tLICENSE TIER\tDESCRIPTION")
	fmt.Fprintln(w, "-------\t------\t--------\t------------\t-----------")

	for _, c := range filtered {
		fmt.Fprintf(w, "felix %s\t%s\t%s\t%s\t%s\n",
			c.Command, c.Engine, c.Maturity, c.LicenseTier, c.Description)
	}
	_ = w.Flush()

	fmt.Println("=========================================================================================")
	fmt.Printf("Total Capabilities: %d (Run 'felix <command> --help' for details on any capability)\n\n", len(filtered))
	return 0
}

func printCapabilitiesHelp() {
	fmt.Println("Usage: felix capabilities [flags]")
	fmt.Println("\nDisplay all registered FELIX 1.0 capabilities, vulnerability engines, and maturity levels.")
	fmt.Println("\nFlags:")
	fmt.Println("  --catalogue, --vulns   Display the comprehensive master vulnerability intelligence catalog")
	fmt.Println("  --json                 Output capability matrix as JSON")
	fmt.Println("  --tier <tier>          Filter by license tier (COMMUNITY, PROFESSIONAL, ENTERPRISE)")
	fmt.Println("  --maturity <status>    Filter by maturity level (PRODUCTION-GRADE, LAB-TESTED)")
	fmt.Println("  --help, -h             Show this help message")
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
