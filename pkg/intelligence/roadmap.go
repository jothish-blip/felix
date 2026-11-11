package intelligence

import (
	"fmt"
	"strings"
	"time"

	"felix/pkg/report"
)

// RemediationPriority categorizes actionable remediation tasks by urgency.
type RemediationPriority string

const (
	PriorityP1Critical RemediationPriority = "P1_CRITICAL" // Immediate attention (< 7 days): Critical exploitability / data loss
	PriorityP2High     RemediationPriority = "P2_HIGH"     // High priority (< 30 days): Direct authorization or injection exposure
	PriorityP3Medium   RemediationPriority = "P3_MEDIUM"   // Medium priority (< 60 days): Misconfigurations, missing defense-in-depth
	PriorityP4Low      RemediationPriority = "P4_LOW"      // Low / Hygiene (< 90 days): Informational and hardening observations
)

// RemediationTask represents a concrete, prioritized action item for developers and engineers.
type RemediationTask struct {
	FindingID              string              `json:"finding_id"`
	VulnClassification     string              `json:"vuln_classification"`
	AffectedAsset          string              `json:"affected_asset"`
	Endpoint               string              `json:"endpoint"`
	Evidence               string              `json:"evidence"`
	Severity               string              `json:"severity"`
	Confidence             string              `json:"confidence"`
	BusinessImpact         string              `json:"business_impact"`
	RecommendedRemediation string              `json:"recommended_remediation"`
	CodeDiffSnippet        string              `json:"code_diff_snippet,omitempty"`
	VerificationSteps      string              `json:"verification_steps"`
	Priority               RemediationPriority `json:"priority"`
	Dependencies           []string            `json:"dependencies,omitempty"`
}

// RemediationRoadmap is the executive- and engineering-ready prioritized remediation plan.
type RemediationRoadmap struct {
	TargetURL    string            `json:"target_url"`
	GeneratedAt  time.Time         `json:"generated_at"`
	TotalTasks   int               `json:"total_tasks"`
	P1Count      int               `json:"p1_count"`
	P2Count      int               `json:"p2_count"`
	P3Count      int               `json:"p3_count"`
	P4Count      int               `json:"p4_count"`
	Tasks        []RemediationTask `json:"tasks"`
}

// GenerateRoadmap constructs a structured, realistic remediation roadmap from assessment findings.
func GenerateRoadmap(findings []report.Finding, targetURL string) *RemediationRoadmap {
	roadmap := &RemediationRoadmap{
		TargetURL:   targetURL,
		GeneratedAt: time.Now().UTC(),
		Tasks:       make([]RemediationTask, 0, len(findings)),
	}

	for _, f := range findings {
		task := buildRemediationTask(f)
		roadmap.Tasks = append(roadmap.Tasks, task)
		roadmap.TotalTasks++

		switch task.Priority {
		case PriorityP1Critical:
			roadmap.P1Count++
		case PriorityP2High:
			roadmap.P2Count++
		case PriorityP3Medium:
			roadmap.P3Count++
		case PriorityP4Low:
			roadmap.P4Count++
		}
	}

	return roadmap
}

func buildRemediationTask(f report.Finding) RemediationTask {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	prio := PriorityP3Medium
	switch sev {
	case "CRITICAL":
		prio = PriorityP1Critical
	case "HIGH":
		prio = PriorityP2High
	case "MEDIUM":
		prio = PriorityP3Medium
	case "LOW", "INFO":
		prio = PriorityP4Low
	}

	impact := determineBusinessImpact(f)
	remediation, diff := determineRemediation(f)
	verification := determineVerificationSteps(f)

	endpoint := f.Target
	if f.Endpoint != "" {
		endpoint = f.Endpoint
	}

	evidenceStr := f.Evidence
	if evidenceStr == "" {
		evidenceStr = f.Description
	}
	if len(evidenceStr) > 200 {
		evidenceStr = evidenceStr[:197] + "..."
	}

	return RemediationTask{
		FindingID:              f.ID,
		VulnClassification:     f.Category,
		AffectedAsset:          f.Target,
		Endpoint:               endpoint,
		Evidence:               evidenceStr,
		Severity:               f.Severity,
		Confidence:             f.Confidence,
		BusinessImpact:         impact,
		RecommendedRemediation: remediation,
		CodeDiffSnippet:        diff,
		VerificationSteps:      verification,
		Priority:               prio,
	}
}

func determineBusinessImpact(f report.Finding) string {
	cat := strings.ToLower(f.Category)
	title := strings.ToLower(f.Title)

	if strings.Contains(cat, "sql") || strings.Contains(title, "sql injection") {
		return "Unauthorized read and write access to primary application database tables; potential complete data exfiltration."
	}
	if strings.Contains(cat, "bola") || strings.Contains(title, "unauthorized cross-user") || strings.Contains(title, "idor") {
		return "Direct unauthorized horizontal privilege escalation allowing attackers to harvest or modify private records belonging to other users."
	}
	if strings.Contains(cat, "bfla") || strings.Contains(title, "administrative bypass") {
		return "Vertical privilege escalation enabling standard unprivileged accounts to invoke system administrative operations."
	}
	if strings.Contains(cat, "secret") || strings.Contains(title, "secret") || strings.Contains(title, "key") {
		return "Exposed authentication credentials or cloud API keys permitting external third-party access to backend infrastructure."
	}
	if strings.Contains(cat, "xss") || strings.Contains(title, "cross-site scripting") {
		return "Execution of arbitrary client-side JavaScript in victim browser sessions; potential session token theft and account takeover."
	}
	if strings.Contains(cat, "ssrf") || strings.Contains(title, "ssrf") {
		return "Unauthorized internal network scanning and cloud instance metadata exfiltration leading to host compromise."
	}
	if strings.Contains(cat, "cors") || strings.Contains(title, "cors") {
		return "Cross-origin websites can instruct authenticated browsers to read confidential API responses."
	}
	if strings.Contains(cat, "header") || strings.Contains(title, "header") {
		return "Lack of browser defense-in-depth protections increases vulnerability to framing (Clickjacking), MIME-sniffing, or protocol downgrade."
	}
	return "Potential degradation of application security posture and non-compliance with industry standards (OWASP / ASVS)."
}

func determineRemediation(f report.Finding) (string, string) {
	title := strings.ToLower(f.Title)
	cat := strings.ToLower(f.Category)

	if strings.Contains(cat, "sql") || strings.Contains(title, "sql injection") {
		return "Refactor database queries to use parameterized prepared statements or an ORM; strictly disallow dynamic string interpolation in SQL.",
			`// Before: db.Query("SELECT * FROM users WHERE id = '" + id + "'")
// After:
db.Query("SELECT * FROM users WHERE id = $1", id)`
	}
	if strings.Contains(cat, "bola") || strings.Contains(title, "cross-user") || strings.Contains(title, "idor") {
		return "Enforce contextual ownership authorization checks at the data layer ensuring the authenticated user ID strictly matches the requested record owner.",
			`// Before: user := db.Find(params["id"])
// After:
user := db.Where("id = ? AND tenant_id = ?", params["id"], session.TenantID).First()`
	}
	if strings.Contains(cat, "bfla") || strings.Contains(title, "administrative") {
		return "Implement strict role-based access control (RBAC) middleware on all administrative route handlers before executing controller logic.",
			`// Enforce authorization guard:
r.Use(middleware.RequireRole("ADMIN"))`
	}
	if strings.Contains(cat, "header") || strings.Contains(title, "content-security-policy") {
		return "Configure Content-Security-Policy header on web server or reverse proxy: default-src 'self'; frame-ancestors 'none'; object-src 'none';",
			`Header set Content-Security-Policy "default-src 'self'; frame-ancestors 'none';"`
	}
	if strings.Contains(title, "clickjacking") || strings.Contains(title, "x-frame-options") {
		return "Set X-Frame-Options: DENY (or SAMEORIGIN) on all HTML responses to prevent unauthorized framing.",
			`Header always set X-Frame-Options "DENY"`
	}
	if strings.Contains(title, "nosniff") {
		return "Set X-Content-Type-Options: nosniff on all HTTP responses.",
			`Header always set X-Content-Type-Options "nosniff"`
	}
	if strings.Contains(cat, "cookie") {
		return "Set Secure, HttpOnly, and SameSite=Lax (or Strict) attributes on all sensitive session cookies.",
			`Set-Cookie: session_id=xyz; Path=/; Secure; HttpOnly; SameSite=Lax`
	}
	if strings.Contains(cat, "secret") {
		return "Revoke the exposed key/token immediately, rotate credentials in cloud provider, and migrate secrets to an environment management service (e.g. AWS Secrets Manager).",
			`// Remove hardcoded key and read from runtime environment:
apiKey := os.Getenv("SERVICE_API_KEY")`
	}

	return "Implement strict input validation, contextual output encoding, and principle-of-least-privilege authorization.", ""
}

func determineVerificationSteps(f report.Finding) string {
	target := f.Target
	if f.Endpoint != "" {
		target = f.Endpoint
	}

	cat := strings.ToLower(f.Category)
	if strings.Contains(cat, "header") || strings.Contains(cat, "cookie") {
		return fmt.Sprintf("curl -I -s %s | grep -iE 'content-security-policy|x-frame-options|set-cookie'", target)
	}
	if strings.Contains(cat, "bola") {
		return fmt.Sprintf("felix assess --target %s --profile api --auth-user-a <token_a> --auth-user-b <token_b>", target)
	}
	return fmt.Sprintf("felix assess --target %s --profile standard --auth-confirm", target)
}

// RenderTerminalSummary returns a formatted CLI representation of the prioritized roadmap.
func (rr *RemediationRoadmap) RenderTerminalSummary() string {
	var sb strings.Builder
	sb.WriteString("\n===========================================================\n")
	sb.WriteString("  FELIX :: AUTOMATED REMEDIATION ROADMAP\n")
	sb.WriteString("===========================================================\n")
	sb.WriteString(fmt.Sprintf("  Target:          %s\n", rr.TargetURL))
	sb.WriteString(fmt.Sprintf("  Total Tasks:     %d (P1 Critical: %d | P2 High: %d | P3 Medium: %d | P4 Low: %d)\n",
		rr.TotalTasks, rr.P1Count, rr.P2Count, rr.P3Count, rr.P4Count))
	sb.WriteString("-----------------------------------------------------------\n")

	if len(rr.Tasks) == 0 {
		sb.WriteString("  [✓] Zero actionable security tasks identified. Target passed all evaluated modules.\n")
		sb.WriteString("===========================================================\n")
		return sb.String()
	}

	for i, t := range rr.Tasks {
		sb.WriteString(fmt.Sprintf("[%d] [%s] %s\n", i+1, t.Priority, t.VulnClassification))
		sb.WriteString(fmt.Sprintf("    Finding ID:    %s\n", t.FindingID))
		sb.WriteString(fmt.Sprintf("    Endpoint:      %s\n", t.Endpoint))
		sb.WriteString(fmt.Sprintf("    Business Risk: %s\n", t.BusinessImpact))
		sb.WriteString(fmt.Sprintf("    Remediation:   %s\n", t.RecommendedRemediation))
		if t.CodeDiffSnippet != "" {
			sb.WriteString(fmt.Sprintf("    Code Patch:    %s\n", strings.ReplaceAll(t.CodeDiffSnippet, "\n", "\n                   ")))
		}
		sb.WriteString(fmt.Sprintf("    Verify:        %s\n", t.VerificationSteps))
		sb.WriteString("-----------------------------------------------------------\n")
	}

	return sb.String()
}
