package report

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// ReproductionOutcome represents the execution result classification of a step.
type ReproductionOutcome string

const (
	ReproductionOutcomeVerified           ReproductionOutcome = "VERIFIED"
	ReproductionOutcomeNotVerified        ReproductionOutcome = "NOT_VERIFIED"
	ReproductionOutcomeInconclusive       ReproductionOutcome = "INCONCLUSIVE"
	ReproductionOutcomeSkippedUnsafe      ReproductionOutcome = "SKIPPED_UNSAFE"
	ReproductionOutcomeConfigError        ReproductionOutcome = "CONFIGURATION_ERROR"
	ReproductionOutcomeManualVerification ReproductionOutcome = "MANUAL_VERIFICATION_REQUIRED"
)

// ReproductionStep represents a single planned verification check in the reproduction script.
type ReproductionStep struct {
	StepNumber       int               `json:"step_number"`
	SourceFindingID  string            `json:"source_finding_id"`
	TargetFindingID  string            `json:"target_finding_id,omitempty"`
	FindingTitle     string            `json:"finding_title"`
	Category         string            `json:"category"`
	RuleCode         string            `json:"rule_code,omitempty"`
	RuleName         string            `json:"rule_name,omitempty"`
	IsSafelyRunnable bool              `json:"is_safely_runnable"`
	UnsafeReason     string            `json:"unsafe_reason,omitempty"`
	ManualChecklist  []string          `json:"manual_checklist,omitempty"`

	// Request details
	HTTPMethod  string            `json:"http_method"`
	Endpoint    string            `json:"endpoint"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyPayload string            `json:"body_payload,omitempty"`

	// Verification predicate
	ExpectedStatuses []int  `json:"expected_statuses,omitempty"`
	ExpectedHeader   string `json:"expected_header,omitempty"`
	ExpectedPattern  string `json:"expected_pattern,omitempty"`
	NegativeCheck    bool   `json:"negative_check,omitempty"`
	Explanation      string `json:"explanation"`
}

// ReproductionScriptPlan contains the planned reproduction procedure for an attack path or finding.
type ReproductionScriptPlan struct {
	ChainID            string             `json:"chain_id"`
	ChainTitle         string             `json:"chain_title"`
	PathStatus         string             `json:"path_status"`
	AssessmentRef      string             `json:"assessment_ref,omitempty"`
	TargetAsset        string             `json:"target_asset,omitempty"`
	EntryPoint         string             `json:"entry_point,omitempty"`
	GeneratedAt        string             `json:"generated_at"`
	Filename           string             `json:"filename"`
	Steps              []ReproductionStep `json:"steps"`
	SafeStepCount      int                `json:"safe_step_count"`
	ManualStepCount    int                `json:"manual_step_count"`
	Prerequisites      []string           `json:"prerequisites"`
	SafetyNotes        []string           `json:"safety_notes"`
	ShellScriptContent string             `json:"-"`
}

// ReproductionOptions configures script generation.
type ReproductionOptions struct {
	TargetOrigin  string // optional base origin (e.g. "https://api.example.com")
	AssessmentRef string // assessment reference or identifier
	OutputFile    string // optional custom output filepath
	Overwrite     bool   // allow overwriting existing output file
}

// SanitizeScriptFilename converts an attack path or chain ID into a safe, collision-resistant
// filename conforming to reproduce_chain_<id>.sh format.
func SanitizeScriptFilename(chainID string) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, strings.TrimSpace(chainID))

	for strings.Contains(clean, "__") || strings.Contains(clean, "--") || strings.Contains(clean, "_-") || strings.Contains(clean, "-_") {
		clean = strings.ReplaceAll(clean, "__", "_")
		clean = strings.ReplaceAll(clean, "--", "-")
		clean = strings.ReplaceAll(clean, "_-", "_")
		clean = strings.ReplaceAll(clean, "-_", "_")
	}
	clean = strings.Trim(clean, "_-")
	if clean == "" {
		clean = "unnamed_chain"
	}
	return fmt.Sprintf("reproduce_chain_%s.sh", clean)
}

// ShellEscape securely quotes a string literal for POSIX Bash using standard single-quote wrapping.
func ShellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

var (
	validMethodRegex       = regexp.MustCompile(`^[A-Z]{3,7}$`)
	destructiveMethodRegex = regexp.MustCompile(`(?i)^(POST|DELETE|PUT|PATCH|DROP|ALTER|UNLINK)$`)
	destructiveSQLRegex    = regexp.MustCompile(`(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE|DELETE\s+FROM|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|INSERT\s+INTO)\b`)
	rcePatternRegex        = regexp.MustCompile(`(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell|whoami|cat\s+/etc/passwd|nc\s+-e|bash\s+-i|wget\s+http|curl\s+http.*\|\s*sh)`)
)

// PlanReproductionScript inspects an AttackPathSummary and its associated findings to plan
// an evidence-backed, non-destructive reproduction procedure.
func PlanReproductionScript(path AttackPathSummary, findings []Finding, opts ReproductionOptions) (*ReproductionScriptPlan, error) {
	findingMap := make(map[string]Finding, len(findings))
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	// Ensure graph nodes are enriched if missing
	if len(path.GraphNodes) == 0 {
		EnrichAttackPathGraph(&path, findings)
	}

	pathStatus := path.Status
	if pathStatus == "" {
		pathStatus = "CONFIRMED"
	}

	plan := &ReproductionScriptPlan{
		ChainID:       path.ID,
		ChainTitle:    path.Title,
		PathStatus:    pathStatus,
		AssessmentRef: opts.AssessmentRef,
		TargetAsset:   path.TargetAsset,
		EntryPoint:    path.EntryPoint,
		GeneratedAt:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Filename:      SanitizeScriptFilename(path.ID),
		Prerequisites: []string{
			"Bash shell (Linux, macOS, or Windows Git Bash / WSL)",
			"curl 7.60+ with standard HTTPS / TLS support",
			"Authorized access to target origin with designated test credentials (if authenticated)",
		},
		SafetyNotes: []string{
			"Strict non-destructive policy: no data modification, no credentials replay, no destructive SQL, no shell command execution.",
			"Target origin must be explicitly authorized by operator via TARGET_ORIGIN environment variable or interactive prompt.",
			"Redirects escaping authorized origin, scheme, hostname, or port are blocked.",
		},
	}

	if opts.OutputFile != "" {
		plan.Filename = filepath.Base(opts.OutputFile)
	}

	// Map edge transitions by source ID for relationship lookups
	edgeBySource := make(map[string]AttackPathEdge)
	for _, e := range path.GraphEdges {
		edgeBySource[e.SourceID] = e
	}

	// Iterate over path nodes to build reproduction steps
	for i, node := range path.GraphNodes {
		f, hasFinding := findingMap[node.ID]

		stepNum := i + 1
		step := ReproductionStep{
			StepNumber:      stepNum,
			SourceFindingID: node.ID,
			FindingTitle:    node.Title,
			Category:        node.Category,
		}

		if hasFinding && f.Category != "" {
			step.Category = f.Category
		}

		// Transition edge context
		if edge, hasEdge := edgeBySource[node.ID]; hasEdge {
			step.TargetFindingID = edge.TargetID
			step.RuleCode = edge.RuleCode
			step.RuleName = edge.RuleName
			step.Explanation = edge.Explanation
		}

		// Extract endpoint from node or finding
		rawEndpoint := node.Endpoint
		if rawEndpoint == "" && hasFinding {
			rawEndpoint = f.Endpoint
			if rawEndpoint == "" {
				rawEndpoint = f.Target
			}
		}

		// Normalize endpoint path (strip scheme and host if full URL)
		endpointPath := sanitizeEndpointPath(rawEndpoint)
		step.Endpoint = endpointPath

		// Determine HTTP Method
		method := "GET"
		if hasFinding && f.Method != "" {
			method = strings.ToUpper(strings.TrimSpace(f.Method))
		}
		step.HTTPMethod = method

		// Determine safe execution vs manual verification
		isSafe, unsafeReason, checklist := evaluateStepSafety(node, f, method, endpointPath)
		step.IsSafelyRunnable = isSafe
		step.UnsafeReason = unsafeReason
		step.ManualChecklist = checklist

		if isSafe {
			plan.SafeStepCount++
			// Determine verification predicate
			step.ExpectedStatuses = determineExpectedStatuses(f, node)
			step.ExpectedPattern = extractSafeEvidencePattern(f)
			if step.Explanation == "" {
				step.Explanation = fmt.Sprintf("Verify reachable state and evidence condition for %s [%s]", node.ID, node.Title)
			}
		} else {
			plan.ManualStepCount++
		}

		plan.Steps = append(plan.Steps, step)
	}

	return plan, nil
}

// evaluateStepSafety inspects request parameters and finding characteristics against the non-destructive policy.
func evaluateStepSafety(node AttackPathNode, f Finding, method, endpoint string) (bool, string, []string) {
	// 1. Prohibited HTTP methods & method allowlist
	// Strictly permit GET, HEAD, OPTIONS by default; deny POST and state-changing methods.
	if !validMethodRegex.MatchString(method) {
		return false, fmt.Sprintf("HTTP method %q contains invalid characters or unsupported format.", method), []string{
			"1. Verify HTTP request syntax in endpoint specifications.",
		}
	}

	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return false, fmt.Sprintf("HTTP method %s is state-changing or not in read-only allowlist (only GET, HEAD, OPTIONS are permitted).", method), []string{
			"1. Review API endpoint documentation for safe read-only query alternatives.",
			"2. Perform test within an isolated development sandbox using dedicated disposable test records.",
			"3. Confirm whether role-based access controls reject unauthorized access without running state-modifying operations.",
		}
	}

	// 2. Destructive SQL injection
	evidenceText := f.Evidence + " " + f.EvidenceDetails.Observation + " " + f.EvidenceDetails.ObservedBehavior
	if destructiveSQLRegex.MatchString(evidenceText) || destructiveSQLRegex.MatchString(endpoint) {
		return false, "Destructive SQL statement detected in finding evidence; automatic execution prohibited to protect database integrity.", []string{
			"1. Inspect application source code to verify whether query construction uses parameterized statements.",
			"2. In a staging environment, supply a benign single quote or parameter syntax probe to test error handling.",
			"3. Review database query logs to verify if inputs escape intended parameter boundaries.",
		}
	}

	// 3. Remote Code Execution / Arbitrary Command Execution
	catUpper := strings.ToUpper(node.Category)
	if strings.Contains(catUpper, "INJECTION & EXECUTION") || strings.Contains(catUpper, "REMOTE CODE EXECUTION") || strings.Contains(catUpper, "RCE") || rcePatternRegex.MatchString(evidenceText) {
		if !strings.Contains(f.Verification.SafeCurlCommand, "cmd=id") && !strings.Contains(f.Verification.SafeCurlCommand, "whoami") && f.Verification.SafeCurlCommand != "" {
			// Safe probe available
		} else {
			return false, "Remote code execution proof requires command execution payloads, which are prohibited by safety policy.", []string{
				"1. Review endpoint source code and handler definitions for dynamic expression evaluation or shell execution sinks.",
				"2. Verify whether endpoint authentication barriers are active by sending unauthenticated benign probes.",
				"3. Inspect ingress proxy rules to confirm management interfaces are isolated from external networks.",
			}
		}
	}

	// 4. Missing endpoint
	if endpoint == "" || endpoint == "/" {
		if node.Category != "" && !strings.Contains(strings.ToLower(node.Title), "root") {
			return false, "Finding lacks a concrete, evidence-backed endpoint path; automated probe cannot be constructed safely.", []string{
				"1. Consult application routing tables or access logs to locate the exact handler.",
				"2. Verify whether the component is reachable via internal service mesh or staging endpoints.",
			}
		}
	}

	return true, "", nil
}

// sanitizeEndpointPath ensures the endpoint path is relative to target origin, scrubbed of credentials,
// and safe from shell escape sequences.
func sanitizeEndpointPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}

	// Remove carriage returns, newlines, and null bytes
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.ReplaceAll(raw, "\n", "")
	raw = strings.ReplaceAll(raw, "\x00", "")

	// If full URL, extract path and query
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err == nil {
			path := u.Path
			if path == "" {
				path = "/"
			}
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			raw = path
		}
	}

	// Clean out any credentials if accidentally present
	raw = secrets.SanitizeURL(raw)

	// Ensure leading slash
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}

	// Collapse leading multiple slashes to prevent protocol-relative redirects (e.g. //evil.com)
	for strings.HasPrefix(raw, "//") {
		raw = "/" + strings.TrimLeft(raw, "/")
	}

	return raw
}

// determineExpectedStatuses determines the expected HTTP response code based on finding evidence.
func determineExpectedStatuses(f Finding, node AttackPathNode) []int {
	if f.EvidenceDetails.HTTPStatus > 0 {
		return []int{f.EvidenceDetails.HTTPStatus}
	}
	// Default: 200 OK for successful retrieval/bypass
	return []int{200, 204}
}

// extractSafeEvidencePattern retrieves a sanitized, non-sensitive matching substring from empirical evidence.
// It strictly matches only known safe, non-sensitive structural vulnerability signatures
// (e.g. database error tokens, internal configuration constants, or system signatures)
// to prevent arbitrary observations or unredacted secrets from being used as match predicates.
func extractSafeEvidencePattern(f Finding) string {
	// Look for benign structural signatures in Evidence, Observation, or ObservedBehavior
	sources := []string{
		f.Evidence,
		f.EvidenceDetails.Observation,
		f.EvidenceDetails.ObservedBehavior,
	}

	for _, src := range sources {
		if src == "" {
			continue
		}
		lines := strings.Split(src, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			// Match safe structural/vulnerability signatures only:
			if strings.Contains(l, "ADMIN_INTERNAL_KEY") {
				return "ADMIN_INTERNAL_KEY"
			}
			if strings.Contains(l, "PostgreSQL") {
				return "PostgreSQL"
			}
			if strings.Contains(l, "tenant_id") {
				return "tenant_id"
			}
			if strings.Contains(l, "ref: refs/") {
				return "ref: refs/"
			}
			if strings.Contains(l, "BEGIN PRIVATE KEY") {
				return "BEGIN PRIVATE KEY"
			}
			if strings.Contains(l, "root:x:0:0") {
				return "root:x:0:0"
			}
			if strings.Contains(l, "syntax error") {
				return "syntax error"
			}
			if strings.Contains(l, "Access-Control-Allow-Origin") {
				return "Access-Control-Allow-Origin"
			}
		}
	}

	return ""
}

// GenerateReproductionScript builds a complete, standalone, safe Bash reproduction script.
func GenerateReproductionScript(path AttackPathSummary, findings []Finding, opts ReproductionOptions) (*ReproductionScriptPlan, error) {
	plan, err := PlanReproductionScript(path, findings, opts)
	if err != nil {
		return nil, err
	}

	var sb bytes.Buffer

	// 1. Script Header and Documentation
	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("# ==============================================================================\n")
	sb.WriteString("# FELIX Proof-of-Exploit (PoE) Reproduction Script\n")
	fmt.Fprintf(&sb, "# Chain ID:        %s\n", plan.ChainID)
	fmt.Fprintf(&sb, "# Title:           %s\n", plan.ChainTitle)
	fmt.Fprintf(&sb, "# Path Status:     %s\n", plan.PathStatus)
	if plan.AssessmentRef != "" {
		fmt.Fprintf(&sb, "# Assessment Ref:  %s\n", plan.AssessmentRef)
	}
	if plan.TargetAsset != "" {
		fmt.Fprintf(&sb, "# Target Asset:    %s\n", plan.TargetAsset)
	}
	fmt.Fprintf(&sb, "# Generated At:    %s\n", plan.GeneratedAt)
	sb.WriteString("# Policy:          Strict Non-Destructive Read-Only Verification\n")
	sb.WriteString("# ==============================================================================\n")
	sb.WriteString("# NOTICE: This script is an evidence-backed verification procedure intended for\n")
	sb.WriteString("# authorized security personnel and engineering leads. It has NOT executed yet.\n")
	sb.WriteString("# Execute this script in an authorized testing or staging environment to verify\n")
	sb.WriteString("# the reported conditions using bounded, non-destructive HTTP requests.\n")
	sb.WriteString("#\n")
	sb.WriteString("# Exit Codes:\n")
	sb.WriteString("#   0 - All planned reproducible checks succeeded (finding conditions verified)\n")
	sb.WriteString("#   1 - Configuration error, invalid target origin, or missing prerequisites\n")
	sb.WriteString("#   2 - One or more reproducible checks failed (condition not observed)\n")
	sb.WriteString("#   3 - Checks completed with inconclusive steps, candidate status, or manual verification required\n")
	sb.WriteString("# ==============================================================================\n\n")

	sb.WriteString("set -euo pipefail\n\n")

	// 2. Terminal Styling
	sb.WriteString("# --- Terminal Formatting & NO_COLOR Support ---\n")
	sb.WriteString("if [ -t 1 ] && [ -z \"${NO_COLOR:-}\" ]; then\n")
	sb.WriteString("  BOLD='\\033[1m'\n")
	sb.WriteString("  RED='\\033[31m'\n")
	sb.WriteString("  GREEN='\\033[32m'\n")
	sb.WriteString("  YELLOW='\\033[33m'\n")
	sb.WriteString("  BLUE='\\033[34m'\n")
	sb.WriteString("  CYAN='\\033[36m'\n")
	sb.WriteString("  RESET='\\033[0m'\n")
	sb.WriteString("else\n")
	sb.WriteString("  BOLD='' RED='' GREEN='' YELLOW='' BLUE='' CYAN='' RESET=''\n")
	sb.WriteString("fi\n\n")

	// 3. Temporary File Setup with Robust Trap & Guard
	sb.WriteString("# --- Safe Isolated Temporary Directory Setup ---\n")
	sb.WriteString("TEMP_DIR=\"$(mktemp -d 2>/dev/null || mktemp -d -t 'felix_poe_XXXXXX')\"\n")
	sb.WriteString("if [ -z \"${TEMP_DIR:-}\" ] || [ \"$TEMP_DIR\" = \"/\" ] || [ ! -d \"$TEMP_DIR\" ]; then\n")
	sb.WriteString("  printf \"${RED}[!] Failed to safely initialize isolated temporary directory.${RESET}\\n\" >&2\n")
	sb.WriteString("  exit 1\n")
	sb.WriteString("fi\n")
	sb.WriteString("trap 'if [ -n \"${TEMP_DIR:-}\" ] && [ \"$TEMP_DIR\" != \"/\" ] && [ -d \"$TEMP_DIR\" ]; then rm -rf \"$TEMP_DIR\"; fi' EXIT INT TERM HUP\n")
	sb.WriteString("RESP_HEADERS=\"$TEMP_DIR/headers.txt\"\n")
	sb.WriteString("RESP_BODY=\"$TEMP_DIR/body.txt\"\n\n")

	// 4. Target Origin Configuration & Scope Validation
	defaultOrigin := ""
	if opts.TargetOrigin != "" {
		defaultOrigin = opts.TargetOrigin
	}
	sb.WriteString("# --- Target Origin Configuration & Scope Validation ---\n")
	fmt.Fprintf(&sb, "TARGET_ORIGIN=\"${TARGET_ORIGIN:-%s}\"\n", defaultOrigin)
	sb.WriteString("if [ -z \"$TARGET_ORIGIN\" ]; then\n")
	sb.WriteString("  if [ -t 0 ]; then\n")
	sb.WriteString("    printf \"${BOLD}Enter authorized target origin [e.g. https://api.example.com]: ${RESET}\"\n")
	sb.WriteString("    read -r TARGET_ORIGIN\n")
	sb.WriteString("  else\n")
	sb.WriteString("    printf \"${RED}[!] Configuration Error: TARGET_ORIGIN environment variable is required in non-interactive mode.${RESET}\\n\" >&2\n")
	fmt.Fprintf(&sb, "    printf \"Usage: TARGET_ORIGIN=https://target.example.com %%s\\n\" \"$0\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("  fi\n")
	sb.WriteString("fi\n\n")

	sb.WriteString("# Trim trailing slash\n")
	sb.WriteString("TARGET_ORIGIN=\"${TARGET_ORIGIN%/}\"\n\n")

	sb.WriteString("# Validate Scheme and Origin Hostname (reject embedded credentials and shell metacharacters)\n")
	sb.WriteString("if [[ ! \"$TARGET_ORIGIN\" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$ ]]; then\n")
	sb.WriteString("  printf \"${RED}[!] Security Policy Violation: Target origin '%s' is malformed, uses an unsupported scheme, or contains unauthorized credentials/characters.${RESET}\\n\" \"$TARGET_ORIGIN\" >&2\n")
	sb.WriteString("  printf \"    Target origin must strictly match: http(s)://hostname[:port]\\n\" >&2\n")
	sb.WriteString("  exit 1\n")
	sb.WriteString("fi\n\n")

	// 5. Target Origin & Safe Request Function (Redirect & Scope Enforcement)
	sb.WriteString("# --- Target Origin & Safe Request Function ---\n")
	sb.WriteString("# felix_safe_request executes a non-destructive HTTP request strictly constrained to TARGET_ORIGIN.\n")
	sb.WriteString("# Redirects escaping the authorized origin, scheme, hostname, or port are blocked.\n")
	sb.WriteString("felix_safe_request() {\n")
	sb.WriteString("  local method=\"$1\"\n")
	sb.WriteString("  local req_path=\"$2\"\n")
	sb.WriteString("  local expects_redirect=\"$3\"\n")
	sb.WriteString("  local hops=0\n")
	sb.WriteString("  local max_hops=3\n")
	sb.WriteString("  local current_url=\"$TARGET_ORIGIN$req_path\"\n\n")
	sb.WriteString("  while [ \"$hops\" -le \"$max_hops\" ]; do\n")
	sb.WriteString("    # Verify current_url is strictly within authorized TARGET_ORIGIN\n")
	sb.WriteString("    if [[ ! \"$current_url\" =~ ^\"$TARGET_ORIGIN\"(/.*|\\?.*|$)$ ]]; then\n")
	sb.WriteString("      printf \"  ${RED}[!] Security Policy: Request destination '%s' escapes authorized TARGET_ORIGIN '%s'. Request blocked.${RESET}\\n\" \"$current_url\" \"$TARGET_ORIGIN\" >&2\n")
	sb.WriteString("      HTTP_CODE=\"REDIRECT_BLOCKED\"\n")
	sb.WriteString("      return 0\n")
	sb.WriteString("    fi\n\n")
	sb.WriteString("    HTTP_CODE=$(curl -sS --max-time 10 --connect-timeout 5 \\\n")
	sb.WriteString("      --proto =http,https \\\n")
	sb.WriteString("      -X \"$method\" \\\n")
	sb.WriteString("      -D \"$RESP_HEADERS\" \\\n")
	sb.WriteString("      -o \"$RESP_BODY\" \\\n")
	sb.WriteString("      -w \"%{http_code}\" \\\n")
	sb.WriteString("      -- \"$current_url\" || echo \"000\")\n\n")
	sb.WriteString("    # If curl failed or returned non-redirect status, stop\n")
	sb.WriteString("    if [[ ! \"$HTTP_CODE\" =~ ^30[12378]$ ]]; then\n")
	sb.WriteString("      return 0\n")
	sb.WriteString("    fi\n\n")
	sb.WriteString("    # If the step explicitly expects a redirect status code, do not follow further\n")
	sb.WriteString("    if [ \"$expects_redirect\" = \"1\" ]; then\n")
	sb.WriteString("      return 0\n")
	sb.WriteString("    fi\n\n")
	sb.WriteString("    # Extract Location header\n")
	sb.WriteString("    local loc\n")
	sb.WriteString("    loc=$(grep -i '^Location:' \"$RESP_HEADERS\" 2>/dev/null | tail -n 1 | tr -d '\\r\\n' | sed -e 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//')\n")
	sb.WriteString("    if [ -z \"$loc\" ]; then\n")
	sb.WriteString("      return 0\n")
	sb.WriteString("    fi\n\n")
	sb.WriteString("    hops=$((hops + 1))\n")
	sb.WriteString("    if [ \"$hops\" -gt \"$max_hops\" ]; then\n")
	sb.WriteString("      printf \"  ${YELLOW}[!] Maximum redirects (%d) reached.${RESET}\\n\" \"$max_hops\" >&2\n")
	sb.WriteString("      return 0\n")
	sb.WriteString("    fi\n\n")
	sb.WriteString("    # Resolve destination URL\n")
	sb.WriteString("    if [[ \"$loc\" =~ ^/ ]]; then\n")
	sb.WriteString("      current_url=\"$TARGET_ORIGIN$loc\"\n")
	sb.WriteString("    elif [[ \"$loc\" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then\n")
	sb.WriteString("      current_url=\"$loc\"\n")
	sb.WriteString("      # Immediately validate destination origin\n")
	sb.WriteString("      if [[ ! \"$current_url\" =~ ^\"$TARGET_ORIGIN\"(/.*|\\?.*|$)$ ]]; then\n")
	sb.WriteString("        printf \"  ${RED}[!] Security Policy: Redirect destination '%s' escapes authorized TARGET_ORIGIN '%s'. Cross-origin redirect blocked.${RESET}\\n\" \"$loc\" \"$TARGET_ORIGIN\" >&2\n")
	sb.WriteString("        HTTP_CODE=\"REDIRECT_BLOCKED\"\n")
	sb.WriteString("        return 0\n")
	sb.WriteString("      fi\n")
	sb.WriteString("    else\n")
	sb.WriteString("      current_url=\"$TARGET_ORIGIN/$loc\"\n")
	sb.WriteString("    fi\n")
	sb.WriteString("  done\n")
	sb.WriteString("}\n\n")

	// 6. Interactive Confirmation
	sb.WriteString("# --- Interactive Execution Confirmation ---\n")
	sb.WriteString("NON_INTERACTIVE=\"${NON_INTERACTIVE:-0}\"\n")
	sb.WriteString("if [ \"$NON_INTERACTIVE\" != \"1\" ] && [ -t 0 ]; then\n")
	sb.WriteString("  printf \"\\n${BOLD}================================================================${RESET}\\n\"\n")
	fmt.Fprintf(&sb, "  printf \"${BOLD}FELIX Chain Verification:${RESET} %%s\\n\" %s\n", ShellEscape(plan.ChainID))
	fmt.Fprintf(&sb, "  printf \"${BOLD}Chain Title:${RESET}              %%s\\n\" %s\n", ShellEscape(plan.ChainTitle))
	fmt.Fprintf(&sb, "  printf \"${BOLD}Path Status:${RESET}              %%s\\n\" %s\n", ShellEscape(plan.PathStatus))
	sb.WriteString("  printf \"${BOLD}Target Origin:${RESET}            %s\\n\" \"$TARGET_ORIGIN\"\n")
	fmt.Fprintf(&sb, "  printf \"${BOLD}Planned Checks:${RESET}           %%d reproducible, %%d manual verification\\n\" %d %d\n", plan.SafeStepCount, plan.ManualStepCount)
	sb.WriteString("  printf \"${BOLD}================================================================${RESET}\\n\"\n")
	sb.WriteString("  printf \"Proceed with non-destructive verification against target? [y/N]: \"\n")
	sb.WriteString("  read -r CONFIRM\n")
	sb.WriteString("  if [[ ! \"$CONFIRM\" =~ ^[yY]([eE][sS])?$ ]]; then\n")
	sb.WriteString("    printf \"Aborted by operator.\\n\"\n")
	sb.WriteString("    exit 0\n")
	sb.WriteString("  fi\n")
	sb.WriteString("fi\n\n")

	// 7. Summary Counters and Chain Broken Guard
	sb.WriteString("# --- Verification Counters & Chain State ---\n")
	sb.WriteString("TOTAL_VERIFIED=0\n")
	sb.WriteString("TOTAL_NOT_VERIFIED=0\n")
	sb.WriteString("TOTAL_INCONCLUSIVE=0\n")
	sb.WriteString("TOTAL_MANUAL=0\n")
	sb.WriteString("CHAIN_BROKEN=0\n\n")

	// 8. Render Each Planned Step
	for _, step := range plan.Steps {
		fmt.Fprintf(&sb, "# ------------------------------------------------------------------------------\n")
		fmt.Fprintf(&sb, "# Step %d: %s [%s]\n", step.StepNumber, step.SourceFindingID, step.FindingTitle)
		fmt.Fprintf(&sb, "# Category: %s\n", step.Category)
		if step.RuleCode != "" {
			fmt.Fprintf(&sb, "# Rule:     %s - %s\n", step.RuleCode, step.RuleName)
		}
		fmt.Fprintf(&sb, "# ------------------------------------------------------------------------------\n")
		fmt.Fprintf(&sb, "printf \"\\n${CYAN}----------------------------------------------------------------${RESET}\\n\"\n")
		fmt.Fprintf(&sb, "printf \"${BOLD}[Step %d/%d] %%s: %%s${RESET}\\n\" %s %s\n",
			step.StepNumber, len(plan.Steps), ShellEscape(step.SourceFindingID), ShellEscape(step.FindingTitle))

		if step.IsSafelyRunnable {
			// Check prerequisite chain continuity
			sb.WriteString("if [ \"$CHAIN_BROKEN\" = \"1\" ]; then\n")
			fmt.Fprintf(&sb, "  printf \"  Result:   ${YELLOW}[SKIPPED]${RESET} Prerequisite step failed or was blocked; dependent check for %s halted.\\n\"\n", ShellEscape(step.SourceFindingID))
			sb.WriteString("  TOTAL_NOT_VERIFIED=$((TOTAL_NOT_VERIFIED + 1))\n")
			sb.WriteString("else\n")

			fmt.Fprintf(&sb, "  printf \"  Endpoint:  %s %%s\\n\" \"$TARGET_ORIGIN%s\"\n", step.HTTPMethod, step.Endpoint)
			fmt.Fprintf(&sb, "  printf \"  Objective: %%s\\n\" %s\n", ShellEscape(step.Explanation))

			// Determine if step expects redirect
			expectsRedirect := 0
			for _, code := range step.ExpectedStatuses {
				if code >= 301 && code <= 308 {
					expectsRedirect = 1
					break
				}
			}

			// Invoke felix_safe_request with safe single-quoted path variable
			fmt.Fprintf(&sb, "  REQ_PATH=%s\n", ShellEscape(step.Endpoint))
			fmt.Fprintf(&sb, "  felix_safe_request %s \"$REQ_PATH\" \"%d\"\n\n", ShellEscape(step.HTTPMethod), expectsRedirect)

			// Predicate Evaluation
			sb.WriteString("  # Evaluate Verification Predicate\n")
			sb.WriteString("  if [ \"$HTTP_CODE\" = \"REDIRECT_BLOCKED\" ]; then\n")
			sb.WriteString("    printf \"  Result:    ${RED}[NOT_VERIFIED]${RESET} Request or redirect escaped authorized target origin\\n\"\n")
			sb.WriteString("    TOTAL_NOT_VERIFIED=$((TOTAL_NOT_VERIFIED + 1))\n")
			sb.WriteString("    CHAIN_BROKEN=1\n")

			expectedStatusConditions := []string{}
			for _, st := range step.ExpectedStatuses {
				expectedStatusConditions = append(expectedStatusConditions, fmt.Sprintf("[ \"$HTTP_CODE\" = \"%d\" ]", st))
			}
			statusCheck := strings.Join(expectedStatusConditions, " || ")
			if statusCheck == "" {
				statusCheck = "[ \"$HTTP_CODE\" = \"200\" ]"
			}

			if step.ExpectedPattern != "" {
				fmt.Fprintf(&sb, "  elif ( %s ) && grep -qF %s \"$RESP_BODY\"; then\n", statusCheck, ShellEscape(step.ExpectedPattern))
				sb.WriteString("    printf \"  Result:    ${GREEN}[VERIFIED]${RESET} Expected response status and evidence pattern matched\\n\"\n")
				sb.WriteString("    TOTAL_VERIFIED=$((TOTAL_VERIFIED + 1))\n")
				sb.WriteString("  elif [ \"$HTTP_CODE\" = \"000\" ]; then\n")
				sb.WriteString("    printf \"  Result:    ${YELLOW}[INCONCLUSIVE]${RESET} Connection timeout or network unreachable\\n\"\n")
				sb.WriteString("    TOTAL_INCONCLUSIVE=$((TOTAL_INCONCLUSIVE + 1))\n")
				sb.WriteString("    CHAIN_BROKEN=1\n")
				sb.WriteString("  else\n")
				sb.WriteString("    printf \"  Result:    ${RED}[NOT_VERIFIED]${RESET} Expected condition not observed (HTTP %s)\\n\" \"$HTTP_CODE\"\n")
				sb.WriteString("    TOTAL_NOT_VERIFIED=$((TOTAL_NOT_VERIFIED + 1))\n")
				sb.WriteString("    CHAIN_BROKEN=1\n")
				sb.WriteString("  fi\n")
			} else {
				// HTTP 200 alone never proves a vulnerability without a specific evidence-backed predicate
				fmt.Fprintf(&sb, "  elif ( %s ); then\n", statusCheck)
				sb.WriteString("    printf \"  Result:    ${YELLOW}[INCONCLUSIVE]${RESET} Endpoint responded with expected status (HTTP %s) but lacks specific empirical evidence predicate to confirm vulnerability\\n\" \"$HTTP_CODE\"\n")
				sb.WriteString("    TOTAL_INCONCLUSIVE=$((TOTAL_INCONCLUSIVE + 1))\n")
				sb.WriteString("  elif [ \"$HTTP_CODE\" = \"000\" ]; then\n")
				sb.WriteString("    printf \"  Result:    ${YELLOW}[INCONCLUSIVE]${RESET} Connection timeout or network unreachable\\n\"\n")
				sb.WriteString("    TOTAL_INCONCLUSIVE=$((TOTAL_INCONCLUSIVE + 1))\n")
				sb.WriteString("    CHAIN_BROKEN=1\n")
				sb.WriteString("  else\n")
				sb.WriteString("    printf \"  Result:    ${RED}[NOT_VERIFIED]${RESET} Expected status not returned (HTTP %s)\\n\" \"$HTTP_CODE\"\n")
				sb.WriteString("    TOTAL_NOT_VERIFIED=$((TOTAL_NOT_VERIFIED + 1))\n")
				sb.WriteString("    CHAIN_BROKEN=1\n")
				sb.WriteString("  fi\n")
			}
			sb.WriteString("fi\n\n")
		} else {
			// Manual Verification Step
			sb.WriteString("printf \"  Status:    ${YELLOW}[MANUAL_VERIFICATION_REQUIRED]${RESET}\\n\"\n")
			fmt.Fprintf(&sb, "printf \"  Safety Policy Exclusion: %%s\\n\" %s\n", ShellEscape(step.UnsafeReason))
			if len(step.ManualChecklist) > 0 {
				sb.WriteString("printf \"  Manual Verification Checklist:\\n\"\n")
				for _, item := range step.ManualChecklist {
					fmt.Fprintf(&sb, "printf \"    %%s\\n\" %s\n", ShellEscape(item))
				}
			}
			sb.WriteString("TOTAL_MANUAL=$((TOTAL_MANUAL + 1))\n")
			sb.WriteString("CHAIN_BROKEN=1\n\n")
		}
	}

	// 9. Summary Table and Exit Code Contract
	sb.WriteString("# ==============================================================================\n")
	sb.WriteString("# Reproduction Summary and Final Determination\n")
	sb.WriteString("# ==============================================================================\n")
	sb.WriteString("printf \"\\n${BOLD}================================================================${RESET}\\n\"\n")
	fmt.Fprintf(&sb, "printf \"${BOLD}REPRODUCTION SUMMARY FOR CHAIN: %%s${RESET}\\n\" %s\n", ShellEscape(plan.ChainID))
	sb.WriteString("printf \"  Verified Checks:     %d\\n\" \"$TOTAL_VERIFIED\"\n")
	sb.WriteString("printf \"  Not Verified Checks: %d\\n\" \"$TOTAL_NOT_VERIFIED\"\n")
	sb.WriteString("printf \"  Inconclusive Checks: %d\\n\" \"$TOTAL_INCONCLUSIVE\"\n")
	sb.WriteString("printf \"  Manual / Excluded:   %d\\n\" \"$TOTAL_MANUAL\"\n")
	sb.WriteString("printf \"${BOLD}================================================================${RESET}\\n\"\n\n")

	// Candidate or inconclusive paths are not presented as verified
	if plan.PathStatus != "CONFIRMED" && plan.PathStatus != "VERIFIED" {
		sb.WriteString("# Candidate or Inconclusive Path: Cannot be presented as fully confirmed/verified\n")
		fmt.Fprintf(&sb, "printf \"${YELLOW}[*] Chain Notice: Attack path status is '%%s' (unverified candidate). Empirical check execution complete.${RESET}\\n\\n\" %s\n", ShellEscape(plan.PathStatus))
		sb.WriteString("if [ \"$TOTAL_NOT_VERIFIED\" -gt 0 ]; then\n")
		sb.WriteString("  printf \"${RED}[!] Final Outcome: NOT VERIFIED - Constituent checks failed to corroborate finding conditions.${RESET}\\n\\n\"\n")
		sb.WriteString("  exit 2\n")
		sb.WriteString("else\n")
		sb.WriteString("  printf \"${YELLOW}[*] Final Outcome: INCONCLUSIVE / CANDIDATE - Checks finished; full exploit chain requires end-to-end confirmation.${RESET}\\n\\n\"\n")
		sb.WriteString("  exit 3\n")
		sb.WriteString("fi\n")
	} else {
		sb.WriteString("# Determine Final Exit Code based on Verification Status\n")
		sb.WriteString("if [ \"$TOTAL_NOT_VERIFIED\" -gt 0 ]; then\n")
		sb.WriteString("  printf \"${RED}[!] Final Outcome: NOT VERIFIED - One or more reproducible checks failed to corroborate finding conditions.${RESET}\\n\\n\"\n")
		sb.WriteString("  exit 2\n")
		sb.WriteString("elif [ \"$TOTAL_INCONCLUSIVE\" -gt 0 ] || [ \"$TOTAL_MANUAL\" -gt 0 ]; then\n")
		sb.WriteString("  printf \"${YELLOW}[*] Final Outcome: INCONCLUSIVE / PARTIAL - Checks finished with inconclusive results or manual verification items.${RESET}\\n\\n\"\n")
		sb.WriteString("  exit 3\n")
		sb.WriteString("else\n")
		sb.WriteString("  printf \"${GREEN}[+] Final Outcome: VERIFIED - All planned reproducible finding conditions successfully observed.${RESET}\\n\\n\"\n")
		sb.WriteString("  exit 0\n")
		sb.WriteString("fi\n")
	}

	plan.ShellScriptContent = secrets.RedactText(sb.String())
	return plan, nil
}

// WriteReproductionScript generates and writes the standalone reproduction script to disk.
func WriteReproductionScript(path AttackPathSummary, findings []Finding, opts ReproductionOptions) (string, error) {
	plan, err := GenerateReproductionScript(path, findings, opts)
	if err != nil {
		return "", err
	}

	outPath := plan.Filename
	if opts.OutputFile != "" {
		outPath = opts.OutputFile
	}

	// Check if file exists when overwrite is false
	if !opts.Overwrite {
		if _, err := os.Stat(outPath); err == nil {
			return "", fmt.Errorf("output file %q already exists; use --overwrite to replace it", outPath)
		}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(outPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Atomic write: write to unique temporary file in the same directory, then rename
	tmpFile := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%d", filepath.Base(outPath), time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(plan.ShellScriptContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write temporary reproduction script: %w", err)
	}

	if opts.Overwrite {
		_ = os.Remove(outPath) // Required on Windows prior to os.Rename
	}

	if err := os.Rename(tmpFile, outPath); err != nil {
		_ = os.Remove(tmpFile)
		return "", fmt.Errorf("failed to atomically save reproduction script to %q: %w", outPath, err)
	}

	return outPath, nil
}
