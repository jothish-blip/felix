package investigation

import (
	"fmt"
	"sort"
	"strings"

	"felix/pkg/report"
)

// GenerateRemediationIntelligence produces immediately actionable remediation guidance tailored to the target.
func GenerateRemediationIntelligence(f report.Finding, targetTech string) *RemediationIntelligence {
	cat := strings.ToUpper(f.Category)
	title := strings.ToUpper(f.Title)

	var (
		rootCause                string
		recommendedFix           string
		implementationGuidance   string
		configurationChanges     []string
		priority                 RemediationPriority
		developerVerification    string
		retestInstructions       string
		frameworkRecommendations []string
		codeSnippet              string
	)

	// Determine framework from tech string or finding evidence
	tech := strings.ToLower(targetTech)
	if tech == "" {
		evidenceLower := strings.ToLower(f.Evidence)
		switch {
		case strings.Contains(evidenceLower, "express") || strings.Contains(evidenceLower, "node"):
			tech = "express/node"
		case strings.Contains(evidenceLower, "django"):
			tech = "django/python"
		case strings.Contains(evidenceLower, "spring"):
			tech = "spring/java"
		case strings.Contains(evidenceLower, "flask"):
			tech = "flask/python"
		case strings.Contains(evidenceLower, "asp.net") || strings.Contains(evidenceLower, "iis"):
			tech = "asp.net"
		case strings.Contains(evidenceLower, "go") || strings.Contains(evidenceLower, "gin"):
			tech = "go"
		default:
			tech = "generic_web"
		}
	}

	switch {
	case strings.Contains(cat, "SQL") || strings.Contains(title, "SQL"):
		priority = PriorityCritical
		rootCause = "Dynamic concatenation of untrusted input into database query strings rather than binding parameters via prepared statements."
		recommendedFix = "Rewrite queries to use parameterized prepared statements or Object-Relational Mapping (ORM) parameter binding."
		implementationGuidance = "Ensure all database calls utilize parameterized queries (? or $1 placeholders). Never interpolate raw string variables into SQL clauses."
		configurationChanges = []string{
			"Disable detailed database error messages in production environment",
			"Configure database user accounts with least-privilege grants (e.g. read-only or single-table access)",
		}
		developerVerification = "Run unit tests executing the function with inputs containing quotes, semicolons, and boolean clauses (e.g. ' OR 1=1 --). Assert that input is treated literally as data."
		retestInstructions = "Execute `felix assess --target <url> --profile standard` or retest specific endpoint. Verify single-quote probes return HTTP 400 Bad Request or normal results with zero syntax errors."
		
		switch {
		case strings.Contains(tech, "node") || strings.Contains(tech, "express"):
			frameworkRecommendations = []string{"Use pg or mysql2 with parameterized queries: `db.query('SELECT * FROM users WHERE id = $1', [userId])`"}
			codeSnippet = "// Node.js pg parameterized query:\nconst result = await pool.query('SELECT * FROM items WHERE id = $1', [req.params.id]);"
		case strings.Contains(tech, "python") || strings.Contains(tech, "django"):
			frameworkRecommendations = []string{"Use Django ORM: `Item.objects.filter(id=item_id)` or cursor parameter substitution"}
			codeSnippet = "# Python DB-API parameterization:\ncursor.execute('SELECT * FROM items WHERE id = %s', (item_id,))"
		case strings.Contains(tech, "go"):
			frameworkRecommendations = []string{"Use database/sql parameter placeholders: `db.QueryContext(ctx, 'SELECT * FROM items WHERE id = ?', id)`"}
			codeSnippet = "// Go database/sql parameterization:\nrow := db.QueryRowContext(ctx, \"SELECT name FROM items WHERE id = ?\", itemID)"
		default:
			codeSnippet = "SELECT * FROM items WHERE id = ?; -- Bind parameter safely at database driver level"
		}

	case strings.Contains(cat, "XSS") || strings.Contains(title, "XSS"):
		priority = PriorityHigh
		rootCause = "Untrusted user input is rendered directly into the HTML document Object Model without contextual output encoding or Content Security Policy enforcement."
		recommendedFix = "Apply contextual HTML entity encoding to all dynamic data before DOM insertion, or utilize auto-escaping template engines."
		implementationGuidance = "Use safe DOM manipulation properties (e.g. `textContent` instead of `innerHTML`). Enforce a strict Content Security Policy (CSP) header."
		configurationChanges = []string{
			"Implement Content-Security-Policy: default-src 'self'; script-src 'self'",
			"Add X-Content-Type-Options: nosniff header to prevent MIME sniffing",
		}
		developerVerification = "Inject HTML and script payloads (`<script>`, `onerror=`, `\"><img src=x>`) into the field. Verify the rendered source code shows `&lt;script&gt;` and no JavaScript executes."
		retestInstructions = "Rerun endpoint audit. Verify input reflections are HTML encoded in the response body."
		codeSnippet = "// Safe DOM binding:\nelement.textContent = userControlledInput; // Safely treated as string, never executable HTML"

	case strings.Contains(cat, "SSRF") || strings.Contains(title, "SSRF"):
		priority = PriorityCritical
		rootCause = "Backend application accepts user-supplied destination URLs and issues outbound network requests without strict IP and domain allowlisting."
		recommendedFix = "Validate and restrict outbound URLs to an explicit allowlist of authorized hostnames and protocols. Block loopback, link-local, and RFC 1918 private IP addresses."
		implementationGuidance = "Resolve hostname before connection, reject any IP matching 127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and disable HTTP redirects."
		configurationChanges = []string{
			"Block egress access to cloud metadata service (169.254.169.254) at network/firewall level",
			"Isolate backend worker services responsible for external URL fetching in a dedicated egress DMZ",
		}
		developerVerification = "Submit localhost and private IP addresses (`http://127.0.0.1`, `http://169.254.169.254`). Verify the application rejects the request with HTTP 400 Bad Request."
		retestInstructions = "Retest endpoint with OAST callback URL. Verify zero outbound HTTP or DNS requests are dispatched."
		codeSnippet = "// Safe egress IP verification:\nip := net.ParseIP(host)\nif ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {\n    return errors.New(\"prohibited egress destination\")\n}"

	case strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR") || strings.Contains(title, "BOLA"):
		priority = PriorityCritical
		rootCause = "Endpoint relies on user-supplied object IDs in routes or request parameters without checking that the authenticated user owns or is authorized to access that object."
		recommendedFix = "Enforce object-level authorization on every data access route by scoping queries to the authenticated user's organization or tenant ID."
		implementationGuidance = "Never query solely by `id = req.params.id`. Query by `id = req.params.id AND tenant_id = req.user.tenantId`."
		configurationChanges = []string{
			"Adopt random GUID/UUID v4 identifiers instead of sequential integers for public object references",
			"Implement centralized policy middleware for object access checks",
		}
		developerVerification = "Write an automated integration test where User A attempts to request User B's object ID. Verify that the response returns HTTP 403 Forbidden or 404 Not Found."
		retestInstructions = "Retest using dual credentials across tenant boundaries. Verify access is refused with 403 Forbidden."
		codeSnippet = "// Scoped tenant access control:\nconst item = await db.findOne({ where: { id: req.params.id, ownerId: req.user.id } });\nif (!item) return res.status(404).send('Not Found');"

	case strings.Contains(cat, "BFLA") || strings.Contains(title, "BFLA") || strings.Contains(title, "FUNCTION LEVEL"):
		priority = PriorityHigh
		rootCause = "Administrative or privileged routes fail to enforce role-based access control (RBAC), allowing any authenticated user to execute privileged operations."
		recommendedFix = "Implement mandatory role and permission checks on all administrative endpoints prior to executing handler logic."
		implementationGuidance = "Use an authorization middleware or guard pattern that verifies `user.roles.includes('ADMIN')` on sensitive API routes."
		configurationChanges = []string{
			"Segregate administrative routes under a separate URL path prefix (e.g. `/api/admin/*`) with uniform middleware protection",
		}
		developerVerification = "Submit a request to the privileged endpoint with a standard user authentication token. Assert the request is rejected with HTTP 403 Forbidden."
		retestInstructions = "Rerun assessment with low-privilege token. Confirm administrative functions fail closed."
		codeSnippet = "// Express RBAC middleware:\napp.use('/api/admin/*', requireAuth, requireRole('ADMIN'));"

	case strings.Contains(cat, "BOPLA") || strings.Contains(title, "BOPLA") ||
		strings.Contains(cat, "PROPERTY LEVEL") || strings.Contains(title, "PROPERTY LEVEL") ||
		strings.Contains(cat, "MASS ASSIGNMENT") || strings.Contains(title, "MASS ASSIGNMENT") ||
		strings.Contains(cat, "EXCESSIVE DATA EXPOSURE") || strings.Contains(title, "EXCESSIVE DATA EXPOSURE"):
		priority = PriorityHigh
		rootCause = "API endpoints serialize raw domain models containing sensitive/internal properties to unauthorized roles, or bind client-supplied request fields directly onto privileged or system-managed object attributes without an explicit field allowlist."
		recommendedFix = "Use explicit role-specific response DTOs for serialization and strict input schema allowlists during request binding so privileged or internal fields cannot be read or overwritten."
		implementationGuidance = "Reject unexpected read-only properties with HTTP 400/403 or ignore them via explicit field projection; filter sensitive properties per caller role before returning JSON responses."
		configurationChanges = []string{
			"Separate internal database structs/ORM entities from public API request and response models",
			"Enable strict JSON unknown-field rejection or schema-validated binding middleware on write endpoints",
		}
		developerVerification = "Issue a GET as a non-admin user and confirm restricted fields are omitted or masked; issue a PUT/PATCH including protected attributes such as role or is_admin and assert via GET read-back that the state remains unchanged."
		retestInstructions = "Retest across identities and read-back endpoints using isolated sessions; confirm zero sensitive field leakage and zero persisted property modification."
		codeSnippet = "// Explicit field projection & safe input allowlist:\ntype ProfileUpdateInput struct { DisplayName string `json:\"display_name\"` }\nvar in ProfileUpdateInput\ndec := json.NewDecoder(r.Body); dec.DisallowUnknownFields()"

	case strings.Contains(cat, "TRAVERSAL") || strings.Contains(title, "TRAVERSAL"):
		priority = PriorityHigh
		rootCause = "File system paths are constructed directly from user input without canonicalization or directory confinement."
		recommendedFix = "Use a fixed base directory, resolve canonical paths using `filepath.Abs`, and verify the resulting path has the base directory as a prefix."
		implementationGuidance = "Reject any filename containing `..`, slashes, or null bytes. Use an indirect map (e.g. file ID to safe path) rather than accepting raw paths."
		configurationChanges = []string{
			"Run application process under a non-root, unprivileged system account with read-only file permissions",
		}
		developerVerification = "Attempt to retrieve `../../../../etc/passwd` or `..\\..\\windows\\win.ini`. Verify server rejects request with 400 Bad Request."
		retestInstructions = "Retest directory traversal probes. Verify all relative path sequences are blocked."
		codeSnippet = "// Safe path confinement:\ncanonicalPath := filepath.Clean(filepath.Join(baseDir, userInput))\nif !strings.HasPrefix(canonicalPath, baseDir) {\n    return errors.New(\"access denied: path traversal attempt\")\n}"

	case strings.Contains(cat, "AUTH") || strings.Contains(title, "AUTHENTICATION"):
		priority = PriorityHigh
		rootCause = "Sensitive API routes or resources are exposed without mandatory authentication barriers or session tokens."
		recommendedFix = "Apply authentication middleware globally by default and explicitly allowlist only public routes."
		implementationGuidance = "Ensure JWT or session tokens are validated on every request. Enforce short token lifespans and secure token signing algorithms."
		configurationChanges = []string{
			"Set `Secure`, `HttpOnly`, and `SameSite=Lax` on all authentication session cookies",
			"Reject JWT tokens with `alg: none` or asymmetric keys verified as HMAC",
		}
		developerVerification = "Issue an unauthenticated HTTP GET/POST to the route. Verify the server returns HTTP 401 Unauthorized."
		retestInstructions = "Issue unauthenticated request. Verify HTTP 401 Unauthorized."
		codeSnippet = "// Default-deny authentication routing:\napp.use(authenticateToken); // Protect all routes by default\napp.use('/api/public', publicRouter); // Explicit opt-in for public routes"

	case strings.Contains(cat, "SECRET") || strings.Contains(title, "CREDENTIAL") || strings.Contains(title, "TOKEN"):
		priority = PriorityHigh
		rootCause = "Sensitive API keys, tokens, or private credentials are embedded in client-accessible assets or source files."
		recommendedFix = "Revoke the exposed credential immediately. Move secret storage to server-side environment variables or a secrets manager."
		implementationGuidance = "Never ship private keys or administrative tokens in client bundles. Use server-side proxy routes for third-party API communication."
		configurationChanges = []string{
			"Rotate and invalidate the exposed API key in the provider management console immediately",
			"Integrate pre-commit git secret scanning hooks into the developer workflow",
		}
		developerVerification = "Inspect production client bundles and network responses. Verify that no cleartext API secrets or private tokens are present."
		retestInstructions = "Rerun secret scanner on web assets. Verify zero credential signatures detected."
		codeSnippet = "# Load secrets from environment:\nAPI_SECRET_KEY = os.environ.get('API_SECRET_KEY')"

	case strings.Contains(cat, "CORS") || strings.Contains(title, "CORS"):
		priority = PriorityMedium
		rootCause = "The CORS configuration reflects arbitrary origins or sets wildcard (`*`) alongside `Access-Control-Allow-Credentials: true`."
		recommendedFix = "Replace wildcard origin reflection with a static allowlist of trusted, authorized domain names."
		implementationGuidance = "Validate the `Origin` header against an explicit list of approved origins. Never combine wildcard `*` with credentials."
		configurationChanges = []string{
			"Configure Access-Control-Allow-Origin to trusted application domains only",
		}
		developerVerification = "Send an OPTIONS preflight request with `Origin: https://evil.example`. Verify `Access-Control-Allow-Origin` is NOT returned."
		retestInstructions = "Send preflight request with untrusted origin. Confirm CORS response rejects external origin."
		codeSnippet = "// Express CORS allowlist:\nconst allowedOrigins = ['https://app.example.com'];\nif (allowedOrigins.includes(req.headers.origin)) {\n    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n}"

	default:
		priority = PriorityMedium
		rootCause = "Application configuration or input handling permits unexpected operational behavior."
		recommendedFix = "Implement input validation, safe operational defaults, and defensive response headers."
		implementationGuidance = "Apply principle of least privilege, strict schema validation, and defensive boundary protections."
		developerVerification = "Inspect server response headers and verify defensive controls are active."
		retestInstructions = "Rerun standard assessment profile against target."
		codeSnippet = "// Apply defensive security headers:\nres.setHeader('X-Content-Type-Options', 'nosniff');\nres.setHeader('X-Frame-Options', 'DENY');"
	}

	return &RemediationIntelligence{
		FindingID:               f.ID,
		RootCause:               rootCause,
		RecommendedFix:          recommendedFix,
		ImplementationGuidance:  implementationGuidance,
		ConfigurationChanges:    configurationChanges,
		Priority:                priority,
		DeveloperVerification:   developerVerification,
		RetestInstructions:      retestInstructions,
		TargetTechnology:        tech,
		FrameworkRecommendations: frameworkRecommendations,
		CodeSnippet:             codeSnippet,
	}
}

// BuildRemediationRoadmap constructs an ordered, prioritized action plan from investigated findings.
func BuildRemediationRoadmap(findings []*InvestigatedFinding) *RemediationRoadmap {
	roadmap := &RemediationRoadmap{
		TotalActions: len(findings),
	}

	type sortableItem struct {
		inf      *InvestigatedFinding
		weight   int
		severity string
	}

	var sortable []sortableItem

	for _, inf := range findings {
		sev := strings.ToUpper(inf.Finding.Severity)
		weight := 5
		switch sev {
		case "CRITICAL":
			roadmap.CriticalCount++
			weight = 1
		case "HIGH":
			roadmap.HighCount++
			weight = 2
		case "MEDIUM":
			roadmap.MediumCount++
			weight = 3
		case "LOW":
			roadmap.LowCount++
			weight = 4
		default:
			roadmap.InfoCount++
			weight = 5
		}
		sortable = append(sortable, sortableItem{
			inf:      inf,
			weight:   weight,
			severity: sev,
		})
	}

	// Sort items by priority weight, then finding ID
	sort.Slice(sortable, func(i, j int) bool {
		if sortable[i].weight != sortable[j].weight {
			return sortable[i].weight < sortable[j].weight
		}
		return sortable[i].inf.Finding.ID < sortable[j].inf.Finding.ID
	})

	for i, item := range sortable {
		inf := item.inf
		action := "Implement defensive validation and verification procedure"
		rootCause := "Unvalidated input or permissive configuration"
		priority := PriorityMedium

		if inf.Remediation != nil {
			action = inf.Remediation.RecommendedFix
			rootCause = inf.Remediation.RootCause
			priority = inf.Remediation.Priority
		}

		roadmap.Items = append(roadmap.Items, RemediationRoadmapItem{
			FixOrder:     i + 1,
			FindingID:    inf.Finding.ID,
			Title:        inf.Finding.Title,
			Severity:     item.severity,
			Endpoint:     inf.Finding.Endpoint,
			RootCause:    rootCause,
			Action:       action,
			Priority:     priority,
			Dependencies: nil,
		})
	}

	return roadmap
}

// RenderTerminalSummary returns an ANSI-formatted terminal summary of the remediation roadmap.
func (r *RemediationRoadmap) RenderTerminalSummary() string {
	if r == nil || len(r.Items) == 0 {
		return "\n===========================================================\n" +
			"  CONTINUOUS REMEDIATION ROADMAP\n" +
			"===========================================================\n" +
			"  No remediation actions required. Target posture is clean.\n" +
			"===========================================================\n"
	}

	var sb strings.Builder
	sb.WriteString("\n===========================================================\n")
	sb.WriteString("  CONTINUOUS REMEDIATION ROADMAP (PRIORITIZED ACTIONS)\n")
	sb.WriteString("===========================================================\n")
	sb.WriteString(fmt.Sprintf("  Total Actions: %d | [P1 Critical: %d] [P2 High: %d] [P3 Medium: %d] [P4 Low: %d]\n",
		r.TotalActions, r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount))
	sb.WriteString("-----------------------------------------------------------\n")

	for _, item := range r.Items {
		badge := fmt.Sprintf("[%s]", item.Priority)
		switch item.Priority {
		case PriorityCritical:
			badge = "\033[1;31m[P1 CRITICAL]\033[0m"
		case PriorityHigh:
			badge = "\033[1;33m[P2 HIGH]\033[0m"
		case PriorityMedium:
			badge = "\033[1;34m[P3 MEDIUM]\033[0m"
		default:
			badge = "\033[1;37m[P4/P5 LOW]\033[0m"
		}

		sb.WriteString(fmt.Sprintf("  #%d. %s %s\n", item.FixOrder, badge, item.Title))
		sb.WriteString(fmt.Sprintf("      Endpoint:   %s\n", item.Endpoint))
		sb.WriteString(fmt.Sprintf("      Root Cause: %s\n", item.RootCause))
		sb.WriteString(fmt.Sprintf("      Fix Action: %s\n", item.Action))
		sb.WriteString("-----------------------------------------------------------\n")
	}

	return sb.String()
}

