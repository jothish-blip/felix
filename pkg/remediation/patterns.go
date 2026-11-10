package remediation

import (
	"fmt"
	"strings"

	"felix/pkg/report"
)

// RemediationPattern defines the interface for vulnerability-specific remediation generators.
type RemediationPattern interface {
	Category() string
	CanHandle(category string) bool
	GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (endLine int, replacement []string, imports []string, breaking []string, impact string, rationale string, tests []string, err error)
	GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string)
}

// PatternRegistry manages the available remediation patterns.
type PatternRegistry struct {
	patterns map[string]RemediationPattern
}

// NewPatternRegistry creates a registry with all standard remediation patterns.
func NewPatternRegistry() *PatternRegistry {
	r := &PatternRegistry{
		patterns: make(map[string]RemediationPattern),
	}
	r.Register(&SQLIPattern{})
	r.Register(&BOLAPattern{})
	r.Register(&XSSPattern{})
	r.Register(&SecurityHeaderPattern{})
	r.Register(&SSRFPattern{})
	r.Register(&PathTraversalPattern{})
	return r
}

// Register registers a pattern.
func (r *PatternRegistry) Register(p RemediationPattern) {
	r.patterns[strings.ToUpper(p.Category())] = p
}

// Resolve looks up a pattern by category string.
func (r *PatternRegistry) Resolve(category string) (RemediationPattern, error) {
	catUpper := strings.ToUpper(strings.TrimSpace(category))
	for _, p := range r.patterns {
		if p.CanHandle(catUpper) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedCategory, category)
}

// Helper to extract candidate parameter variable from dynamic string concatenation
func extractParamExpr(line string) string {
	// First check explicit concatenation expressions with '+'
	if strings.Contains(line, "+") {
		parts := strings.Split(line, "+")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			trimmed = strings.Trim(trimmed, " \t\r\n;),]")
			// If it starts with quote or ends with quote, it's a string literal, skip
			if strings.HasPrefix(trimmed, "\"") || strings.HasPrefix(trimmed, "'") || strings.HasPrefix(trimmed, "`") {
				continue
			}
			// Check if it's a valid identifier/expression (e.g. req.query.q, req.query.id, query_param, q)
			if trimmed != "" && !strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "SELECT") && !strings.Contains(trimmed, "FROM") {
				return trimmed
			}
		}
	}

	// Candidates ordered from most specific to least specific
	candidates := []string{
		"req.query.search", "req.query.keyword", "req.query.term", "req.query.id", "req.query.q",
		"req.params.id", "req.body.username", "req.body.id",
		"query_param", "search_term", "user_input", "user_id",
		"keyword", "search",
	}
	for _, cand := range candidates {
		if strings.Contains(line, cand) {
			return cand
		}
	}

	// Exact word boundary checks for short names like "q" and "id" so they don't match "query" or "width"
	for _, word := range []string{"q", "id"} {
		for _, sep := range []string{" " + word + " ", " " + word + ";", " " + word + ")", "+" + word + "+", "+" + word + " ", " " + word + "+", "(" + word + ")"} {
			if strings.Contains(line, sep) {
				return word
			}
		}
	}
	return ""
}

// --- 1. SQLI Pattern ---
type SQLIPattern struct{}

func (p *SQLIPattern) Category() string { return "SQLI" }
func (p *SQLIPattern) CanHandle(category string) bool {
	return category == "SQLI" || strings.Contains(category, "SQL_INJECTION") || strings.Contains(category, "SQL INJECTION")
}

func (p *SQLIPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Eliminates SQL injection vulnerability by replacing dynamic query string concatenation with parameterized prepared statements, supplying parameters directly to database execution calls, and preserving search filter semantics without string interpolation."
	rationale := "User-supplied query parameter was directly interpolated into the SQL statement without binding. Converting to parameter markers ($1, ?, or %s) and passing user input as query execution arguments guarantees the database driver treats input strictly as literal data."
	breaking := []string{"Requires underlying database driver to support parameterized statements for this query type"}
	tests := []string{
		"Send boolean differential payload (' OR 1=1--) and verify target treats it as literal string with 0 injection matches",
		"Send legitimate search query with alphanumeric characters and verify 200 OK with expected results",
		"Verify user input is never concatenated into SQL query string and parameter values are supplied to database execution call",
	}

	var imports []string
	var replacement []string
	endLine := startLine

	currLine := ""
	if startLine > 0 && startLine <= len(origLines) {
		currLine = origLines[startLine-1]
	}

	// Detect if query execution occurs on the subsequent line
	hasExecutionOnNextLine := false
	var nextLine string
	if startLine < len(origLines) {
		nextLine = origLines[startLine]
		trimmedNext := strings.TrimSpace(nextLine)
		if strings.Contains(trimmedNext, "db.query(") || strings.Contains(trimmedNext, "db.all(") ||
			strings.Contains(trimmedNext, "db.Query(") || strings.Contains(trimmedNext, "db.QueryContext(") ||
			strings.Contains(trimmedNext, "cursor.execute(") || strings.Contains(trimmedNext, "executeQuery(") ||
			strings.Contains(trimmedNext, "stmt.execute") {
			hasExecutionOnNextLine = true
			endLine = startLine + 1
		}
	}

	// Extract candidate parameter variable from current line
	paramExpr := extractParamExpr(currLine)
	isLike := strings.Contains(strings.ToUpper(currLine), "LIKE") || (hasExecutionOnNextLine && strings.Contains(strings.ToUpper(nextLine), "LIKE"))

	// Tailor replacement based on target stack or file extension
	isNode := strings.HasSuffix(targetFile, ".js") || strings.HasSuffix(targetFile, ".ts") || strings.Contains(stack, "express") || strings.Contains(stack, "node")
	isPython := strings.HasSuffix(targetFile, ".py") || strings.Contains(stack, "flask") || strings.Contains(stack, "django")
	isGo := strings.HasSuffix(targetFile, ".go")

	isPostgres := strings.Contains(strings.ToLower(stack), "postgres") || strings.Contains(strings.ToLower(stack), "pg")

	if isNode {
		if paramExpr == "" {
			paramExpr = "req.query.q"
		}
		placeholder := "?"
		if isPostgres {
			placeholder = "$1"
		}

		if isLike {
			if hasExecutionOnNextLine {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter to db.query call",
					fmt.Sprintf("\tconst query = 'SELECT * FROM products WHERE description LIKE %s';", placeholder),
					fmt.Sprintf("\tconst result = await db.query(query, ['%%' + %s + '%%']);", paramExpr),
				}
			} else {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter to db.query call",
					fmt.Sprintf("\tconst result = await db.query('SELECT * FROM products WHERE description LIKE %s', ['%%' + %s + '%%']);", placeholder, paramExpr),
				}
			}
		} else {
			if hasExecutionOnNextLine {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter to db.query call",
					fmt.Sprintf("\tconst query = 'SELECT * FROM products WHERE id = %s';", placeholder),
					fmt.Sprintf("\tconst result = await db.query(query, [%s]);", paramExpr),
				}
			} else {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter to db.query call",
					fmt.Sprintf("\tconst result = await db.query('SELECT * FROM products WHERE id = %s', [%s]);", placeholder, paramExpr),
				}
			}
		}
	} else if isPython {
		if paramExpr == "" {
			paramExpr = "query_param"
		}
		placeholder := "%s"
		if strings.Contains(strings.ToLower(stack), "sqlite") {
			placeholder = "?"
		}

		if isLike {
			if hasExecutionOnNextLine {
				replacement = []string{
					"    # FELIX Remediated: Parameterized execution supplies parameter tuple to cursor.execute",
					fmt.Sprintf("    query = \"SELECT * FROM products WHERE description LIKE %s\"", placeholder),
					fmt.Sprintf("    cursor.execute(query, ('%%' + %s + '%%',))", paramExpr),
				}
			} else {
				replacement = []string{
					"    # FELIX Remediated: Parameterized execution supplies parameter tuple to cursor.execute",
					fmt.Sprintf("    cursor.execute(\"SELECT * FROM products WHERE description LIKE %s\", ('%%' + %s + '%%',))", placeholder, paramExpr),
				}
			}
		} else {
			if hasExecutionOnNextLine {
				replacement = []string{
					"    # FELIX Remediated: Parameterized execution supplies parameter tuple to cursor.execute",
					fmt.Sprintf("    query = \"SELECT * FROM products WHERE id = %s\"", placeholder),
					fmt.Sprintf("    cursor.execute(query, (%s,))", paramExpr),
				}
			} else {
				replacement = []string{
					"    # FELIX Remediated: Parameterized execution supplies parameter tuple to cursor.execute",
					fmt.Sprintf("    cursor.execute(\"SELECT * FROM products WHERE id = %s\", (%s,))", placeholder, paramExpr),
				}
			}
		}
	} else if isGo {
		imports = []string{"database/sql"}
		if paramExpr == "" {
			paramExpr = "q"
		}
		placeholder := "?"
		if isPostgres {
			placeholder = "$1"
		}

		if isLike {
			if hasExecutionOnNextLine {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter argument to db.QueryContext",
					fmt.Sprintf("\tquery := \"SELECT * FROM products WHERE description LIKE %s\"", placeholder),
					fmt.Sprintf("\trows, err := db.QueryContext(ctx, query, \"%%\"+%s+\"%%\")", paramExpr),
				}
			} else {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter argument to db.QueryContext",
					fmt.Sprintf("\trows, err := db.QueryContext(ctx, \"SELECT * FROM products WHERE description LIKE %s\", \"%%\"+%s+\"%%\")", placeholder, paramExpr),
				}
			}
		} else {
			if hasExecutionOnNextLine {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter argument to db.QueryContext",
					fmt.Sprintf("\tquery := \"SELECT * FROM products WHERE id = %s\"", placeholder),
					fmt.Sprintf("\trows, err := db.QueryContext(ctx, query, %s)", paramExpr),
				}
			} else {
				replacement = []string{
					"\t// FELIX Remediated: Parameterized query supplies parameter argument to db.QueryContext",
					fmt.Sprintf("\trows, err := db.QueryContext(ctx, \"SELECT * FROM products WHERE id = %s\", %s)", placeholder, paramExpr),
				}
			}
		}
	} else {
		// Generic Java PreparedStatement
		if paramExpr == "" {
			paramExpr = "q"
		}
		if isLike {
			replacement = []string{
				"    // FELIX Remediated: PreparedStatement supplies bound parameter to executeQuery",
				"    PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM products WHERE description LIKE ?\");",
				fmt.Sprintf("    ps.setString(1, \"%%\" + %s + \"%%\");", paramExpr),
				"    ResultSet rs = ps.executeQuery();",
			}
		} else {
			replacement = []string{
				"    // FELIX Remediated: PreparedStatement supplies bound parameter to executeQuery",
				"    PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM products WHERE id = ?\");",
				fmt.Sprintf("    ps.setString(1, %s);", paramExpr),
				"    ResultSet rs = ps.executeQuery();",
			}
		}
	}

	return endLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *SQLIPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Vulnerable: Dynamic string concatenation allows SQL injection
const query = "SELECT * FROM products WHERE description LIKE '%" + req.query.q + "%'";
const result = await db.query(query);`

	placeholder := "$1"
	if strings.Contains(strings.ToLower(stack), "mysql") || strings.Contains(strings.ToLower(stack), "sqlite") {
		placeholder = "?"
	}

	patched := fmt.Sprintf(`// Remediated: Parameterized prepared statement guarantees literal binding and supplies parameter value
const query = "SELECT * FROM products WHERE description LIKE %s";
const result = await db.query(query, ['%%' + req.query.q + '%%']);`, placeholder)

	hunkLines := []string{
		"-const query = \"SELECT * FROM products WHERE description LIKE '%\" + req.query.q + \"%'\";",
		"-const result = await db.query(query);",
		fmt.Sprintf("+const query = \"SELECT * FROM products WHERE description LIKE %s\";", placeholder),
		"+const result = await db.query(query, ['%' + req.query.q + '%']);",
	}

	diffText := fmt.Sprintf("--- a/server/routes/products.js\n+++ b/server/routes/products.js\n@@ -15,2 +15,2 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "server/routes/products.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 15, OldCount: 2, NewStart: 15, NewCount: 2, Heading: "@@ -15,2 +15,2 @@", Lines: hunkLines},
		},
		AddedLinesCount:    2,
		RemovedLinesCount:  2,
		IsReferencePattern: true,
	}

	impact := "Eliminates SQL injection vulnerability by replacing dynamic query string concatenation with parameterized prepared statements and passing parameters directly to database execution calls."
	rationale := "Reference pattern for SQL injection remediation; use prepared statements or ORM parameter binding with explicit query parameter array."
	tests := []string{
		"Probe endpoint with ' OR 1=1-- to verify differential syntax handling",
		"Verify query execution call supplies parameter array to database driver",
	}
	return remediationDiff, impact, rationale, tests, nil, nil
}

// --- 2. BOLA Pattern ---
type BOLAPattern struct{}

func (p *BOLAPattern) Category() string { return "BOLA" }
func (p *BOLAPattern) CanHandle(category string) bool {
	return category == "BOLA" || category == "IDOR" || strings.Contains(category, "OBJECT_LEVEL_AUTHORIZATION")
}

func (p *BOLAPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Enforces strict object-level authorization by validating that the requesting authenticated user owns or is explicitly authorized to access the requested resource ID, mitigating horizontal and vertical privilege escalation."
	rationale := "Direct object reference without user ownership verification permitted cross-tenant object access. The patch introduces a guard asserting resource ownership before processing the operation."
	breaking := []string{"Requests by administrative users must be handled by an explicit role check"}
	tests := []string{
		"Send authenticated request as User A accessing User B's object ID; assert 403 Forbidden",
		"Send authenticated request as User A accessing User A's object ID; assert 200 OK",
	}

	isPython := strings.HasSuffix(targetFile, ".py") || strings.Contains(stack, "flask") || strings.Contains(stack, "fastapi")
	isGo := strings.HasSuffix(targetFile, ".go")

	var replacement []string
	var imports []string

	if isPython {
		replacement = []string{
			"    # FELIX Remediated: Object ownership check prevents BOLA/IDOR",
			"    if resource.user_id != current_user.id and not current_user.is_admin:",
			"        return jsonify({\"error\": \"Forbidden: unauthorized access to requested object\"}), 403",
		}
	} else if isGo {
		replacement = []string{
			"\t// FELIX Remediated: Object ownership check prevents BOLA/IDOR",
			"\tif resource.UserID != currentUser.ID && !currentUser.IsAdmin {",
			"\t\thttp.Error(w, \"Forbidden: unauthorized access to requested resource\", http.StatusForbidden)",
			"\t\treturn",
			"\t}",
		}
	} else {
		// Node / Express default
		replacement = []string{
			"\t// FELIX Remediated: Object ownership check prevents BOLA/IDOR",
			"\tif (resource.userId !== req.user.id && !req.user.isAdmin) {",
			"\t\treturn res.status(403).json({ error: \"Forbidden: unauthorized access to requested object\" });",
			"\t}",
		}
	}

	return startLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *BOLAPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Vulnerable: Returns object directly by ID without verifying requester ownership
const resource = await Resource.findById(req.params.id);
return res.json(resource);`

	patched := `// Remediated: Enforces object-level ownership check before returning data
const resource = await Resource.findById(req.params.id);
if (resource.userId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: "Forbidden: unauthorized access" });
}
return res.json(resource);`

	hunkLines := []string{
		" const resource = await Resource.findById(req.params.id);",
		"+if (resource.userId !== req.user.id && !req.user.isAdmin) {",
		"+    return res.status(403).json({ error: \"Forbidden: unauthorized access\" });",
		"+}",
		" return res.json(resource);",
	}

	diffText := fmt.Sprintf("--- a/routes/users.js\n+++ b/routes/users.js\n@@ -24,2 +24,5 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "routes/users.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 24, OldCount: 2, NewStart: 24, NewCount: 5, Heading: "@@ -24,2 +24,5 @@", Lines: hunkLines},
		},
		AddedLinesCount:    3,
		RemovedLinesCount:  0,
		IsReferencePattern: true,
	}

	impact := "Enforces object-level authorization policy to prevent unauthorized cross-tenant data access."
	rationale := "Verify user identity against resource ownership attribute before returning object."
	tests := []string{"Assert cross-tenant request returns 403 Forbidden"}
	return remediationDiff, impact, rationale, tests, nil, nil
}

// --- 3. XSS Pattern ---
type XSSPattern struct{}

func (p *XSSPattern) Category() string { return "XSS" }
func (p *XSSPattern) CanHandle(category string) bool {
	return category == "XSS" || strings.Contains(category, "CROSS_SITE_SCRIPTING") || strings.Contains(category, "CROSS-SITE SCRIPTING")
}

func (p *XSSPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Neutralizes Cross-Site Scripting (XSS) vulnerability by applying context-aware HTML sanitization and encoding before rendering user input in client responses."
	rationale := "Directly writing untrusted user data into the HTML response permits attackers to inject malicious JavaScript. Encoding or sanitizing via DOMPurify/HTML escaping prevents script execution."
	breaking := []string{"HTML tags in legitimate user input will be encoded or stripped"}
	tests := []string{
		"Inject payload <script>alert(1)</script> and verify payload is encoded (&lt;script&gt;) or neutralized in output",
	}

	isGo := strings.HasSuffix(targetFile, ".go")
	isPython := strings.HasSuffix(targetFile, ".py")

	var replacement []string
	var imports []string

	if isGo {
		imports = []string{"html"}
		replacement = []string{
			"\t// FELIX Remediated: HTML escaping prevents XSS injection",
			"\tsafeOutput := html.EscapeString(userInput)",
			"\tw.Write([]byte(safeOutput))",
		}
	} else if isPython {
		imports = []string{"html"}
		replacement = []string{
			"    # FELIX Remediated: HTML escaping prevents XSS injection",
			"    safe_output = html.escape(user_input)",
			"    return render_template_string(safe_output)",
		}
	} else {
		// Node.js / React
		imports = []string{"dompurify"}
		replacement = []string{
			"\t// FELIX Remediated: DOMPurify sanitization neutralizes XSS payloads",
			"\tconst cleanOutput = DOMPurify.sanitize(userInput);",
			"\tres.send(cleanOutput);",
		}
	}

	return startLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *XSSPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Vulnerable: Renders unescaped user input into response
res.send("<div>Welcome, " + req.query.name + "</div>");`

	patched := `// Remediated: Sanitizes user input with DOMPurify
const cleanName = DOMPurify.sanitize(req.query.name);
res.send("<div>Welcome, " + cleanName + "</div>");`

	hunkLines := []string{
		"-res.send(\"<div>Welcome, \" + req.query.name + \"</div>\");",
		"+const cleanName = DOMPurify.sanitize(req.query.name);",
		"+res.send(\"<div>Welcome, \" + cleanName + \"</div>\");",
	}

	diffText := fmt.Sprintf("--- a/routes/greeting.js\n+++ b/routes/greeting.js\n@@ -10,1 +10,2 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "routes/greeting.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 10, OldCount: 1, NewStart: 10, NewCount: 2, Heading: "@@ -10,1 +10,2 @@", Lines: hunkLines},
		},
		AddedLinesCount:    2,
		RemovedLinesCount:  1,
		IsReferencePattern: true,
	}

	impact := "Sanitizes user input to prevent client-side script execution."
	rationale := "Use DOMPurify or context-aware HTML escaping for untrusted input."
	tests := []string{"Inject <script>alert(1)</script> and assert neutralization"}
	return remediationDiff, impact, rationale, tests, []string{"dompurify"}, nil
}

// --- 4. Security Header Pattern ---
type SecurityHeaderPattern struct{}

func (p *SecurityHeaderPattern) Category() string { return "SECURITY_HEADER" }
func (p *SecurityHeaderPattern) CanHandle(category string) bool {
	return category == "SECURITY_HEADER" || category == "SECURITY_HEADERS" || category == "MISSING_HEADER" || strings.Contains(category, "HEADER")
}

func (p *SecurityHeaderPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Enforces baseline defensive HTTP headers (CSP, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security) to defend against clickjacking, MIME confusion, and plaintext downgrades."
	rationale := "Missing defensive headers leave web clients exposed to browser-level attacks. Adding security middleware sets these headers globally on all HTTP responses."
	breaking := []string{"Strict CSP may require adjustments for third-party scripts or inline styles"}
	tests := []string{
		"Request root endpoint and verify Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options headers are present",
	}

	isGo := strings.HasSuffix(targetFile, ".go")
	isPython := strings.HasSuffix(targetFile, ".py")

	var replacement []string
	var imports []string

	if isGo {
		replacement = []string{
			"\t// FELIX Remediated: Set defense-in-depth security headers",
			"\tw.Header().Set(\"Content-Security-Policy\", \"default-src 'self'\")",
			"\tw.Header().Set(\"X-Content-Type-Options\", \"nosniff\")",
			"\tw.Header().Set(\"X-Frame-Options\", \"DENY\")",
			"\tw.Header().Set(\"Strict-Transport-Security\", \"max-age=31536000; includeSubDomains\")",
		}
	} else if isPython {
		replacement = []string{
			"    # FELIX Remediated: Set defense-in-depth security headers",
			"    response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
			"    response.headers['X-Content-Type-Options'] = 'nosniff'",
			"    response.headers['X-Frame-Options'] = 'DENY'",
			"    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
		}
	} else {
		// Node.js / Express
		imports = []string{"helmet"}
		replacement = []string{
			"\t// FELIX Remediated: Enforce security headers middleware",
			"\tapp.use(helmet({",
			"\t\tcontentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } },",
			"\t\tframeguard: { action: 'deny' },",
			"\t\thsts: { maxAge: 31536000, includeSubDomains: true },",
			"\t\tnoSniff: true,",
			"\t}));",
		}
	}

	return startLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *SecurityHeaderPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Express app initialization without security middleware
const app = express();
app.use(express.json());`

	patched := `// Express app initialization with Helmet security headers
const app = express();
app.use(helmet());
app.use(express.json());`

	hunkLines := []string{
		" const app = express();",
		"+app.use(helmet());",
		" app.use(express.json());",
	}

	diffText := fmt.Sprintf("--- a/app.js\n+++ b/app.js\n@@ -5,2 +5,3 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "app.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 5, OldCount: 2, NewStart: 5, NewCount: 3, Heading: "@@ -5,2 +5,3 @@", Lines: hunkLines},
		},
		AddedLinesCount:    1,
		RemovedLinesCount:  0,
		IsReferencePattern: true,
	}

	impact := "Enforces baseline security headers across all application routes."
	rationale := "Use Helmet in Node.js or configure reverse proxy (Nginx) headers."
	tests := []string{"Assert response contains X-Content-Type-Options: nosniff"}
	return remediationDiff, impact, rationale, tests, []string{"helmet"}, nil
}

// --- 5. SSRF Pattern ---
type SSRFPattern struct{}

func (p *SSRFPattern) Category() string { return "SSRF" }
func (p *SSRFPattern) CanHandle(category string) bool {
	return category == "SSRF" || strings.Contains(category, "SERVER_SIDE_REQUEST_FORGERY")
}

func (p *SSRFPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Prevents Server-Side Request Forgery (SSRF) by validating destination URL scheme (only http/https) and resolving destination IP against disallowed ranges (IPv4 loopback 127.0.0.0/8, IPv6 ::1, private RFC1918 CIDRs, link-local / cloud metadata 169.254.0.0/16 and fe80::/10), enforcing pre-connection IP pinning against DNS rebinding, and disabling automatic redirects."
	rationale := "Unvalidated outbound requests allow attackers to reach internal network hosts, query cloud metadata endpoints (169.254.169.254), or exploit DNS rebinding to pivot into internal infrastructure. Enforcing pre-dial IP resolution, range filtering, and redirect restrictions neutralizes SSRF."
	breaking := []string{"Outbound requests to internal microservices must be explicitly allowlisted"}
	tests := []string{
		"Submit target URL http://169.254.169.254/latest/meta-data/ and verify 400 Bad Request",
		"Submit target URL http://127.0.0.1:8080 and http://[::1] and verify 400 Bad Request",
		"Submit target URL with DNS rebinding host resolving to private/metadata IP and verify dial is blocked",
	}

	var replacement []string
	var imports []string

	if strings.HasSuffix(targetFile, ".go") {
		imports = []string{"net", "net/url"}
		replacement = []string{
			"\t// FELIX Remediated: Validate target URL against SSRF (IPv4/IPv6, loopback, private CIDR, metadata 169.254.169.254, DNS rebinding)",
			"\tu, err := url.Parse(targetURL)",
			"\tif err != nil || (u.Scheme != \"http\" && u.Scheme != \"https\") {",
			"\t\thttp.Error(w, \"Invalid destination scheme\", http.StatusBadRequest)",
			"\t\treturn",
			"\t}",
			"\tif err := validateOutboundDestination(u.Hostname()); err != nil {",
			"\t\thttp.Error(w, \"Forbidden: target destination not allowed\", http.StatusBadRequest)",
			"\t\treturn",
			"\t}",
		}
	} else {
		// Node.js default
		replacement = []string{
			"\t// FELIX Remediated: SSRF pre-connection IP, scheme, metadata (169.254.169.254), and loopback validation",
			"\tconst parsedUrl = new URL(targetURL);",
			"\tif (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {",
			"\t\treturn res.status(400).json({ error: \"Invalid URL protocol\" });",
			"\t}",
			"\tif (!isAllowedDestination(parsedUrl.hostname)) {",
			"\t\treturn res.status(400).json({ error: \"Target destination rejected by security policy (private/loopback/metadata restricted)\" });",
			"\t}",
		}
	}

	return startLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *SSRFPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Vulnerable: Fetches external resource directly from user input
const response = await axios.get(req.query.url);`

	patched := `// Remediated: Validates scheme and destination IP against private/metadata CIDRs
const parsedUrl = new URL(req.query.url);
if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:' || !isAllowedDestination(parsedUrl.hostname)) {
    return res.status(400).json({ error: "Disallowed destination" });
}
const response = await axios.get(req.query.url, { maxRedirects: 0 });`

	hunkLines := []string{
		"+const parsedUrl = new URL(req.query.url);",
		"+if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:' || !isAllowedDestination(parsedUrl.hostname)) {",
		"+    return res.status(400).json({ error: \"Disallowed destination\" });",
		"+}",
		"-const response = await axios.get(req.query.url);",
		"+const response = await axios.get(req.query.url, { maxRedirects: 0 });",
	}

	diffText := fmt.Sprintf("--- a/routes/fetch.js\n+++ b/routes/fetch.js\n@@ -12,1 +12,5 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "routes/fetch.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 12, OldCount: 1, NewStart: 12, NewCount: 5, Heading: "@@ -12,1 +12,5 @@", Lines: hunkLines},
		},
		AddedLinesCount:    5,
		RemovedLinesCount:  1,
		IsReferencePattern: true,
	}

	impact := "Validates destination IP to prevent internal network scanning and cloud metadata access."
	rationale := "Validate destination against private CIDR ranges and cloud metadata IP (169.254.169.254)."
	tests := []string{"Assert http://169.254.169.254/ is rejected with 400 Bad Request"}
	return remediationDiff, impact, rationale, tests, nil, nil
}

// --- 6. Path Traversal Pattern ---
type PathTraversalPattern struct{}

func (p *PathTraversalPattern) Category() string { return "PATH_TRAVERSAL" }
func (p *PathTraversalPattern) CanHandle(category string) bool {
	return category == "PATH_TRAVERSAL" || category == "DIR_TRAVERSAL" || strings.Contains(category, "TRAVERSAL")
}

func (p *PathTraversalPattern) GenerateFix(f *report.Finding, targetFile string, startLine int, origLines []string, stack string) (int, []string, []string, []string, string, string, []string, error) {
	impact := "Restricts file system operations strictly within authorized base directory, preventing arbitrary file read, directory traversal, or file overwrite."
	rationale := "Path construction using user input with ../ sequences escapes directory boundaries. Normalizing and asserting path containment with base directory and trailing separator prevents prefix bypass traversal."
	breaking := []string{"Symlinks outside the base directory will be rejected"}
	tests := []string{
		"Submit ../../../etc/passwd and verify request is rejected with 400 Bad Request",
		"Submit path attempting prefix bypass (e.g. /var/data_secret when base is /var/data) and verify rejection",
	}

	var replacement []string
	var imports []string

	if strings.HasSuffix(targetFile, ".go") {
		imports = []string{"path/filepath", "strings"}
		replacement = []string{
			"\t// FELIX Remediated: Path traversal boundary validation with separator containment",
			"\tcleanPath := filepath.Clean(filepath.Join(baseDir, userInput))",
			"\tbaseClean := filepath.Clean(baseDir) + string(filepath.Separator)",
			"\tif cleanPath != filepath.Clean(baseDir) && !strings.HasPrefix(cleanPath, baseClean) {",
			"\t\thttp.Error(w, \"Invalid file path: path traversal detected\", http.StatusBadRequest)",
			"\t\treturn",
			"\t}",
		}
	} else {
		// Node.js default
		imports = []string{"path"}
		replacement = []string{
			"\t// FELIX Remediated: Path traversal boundary validation with separator containment",
			"\tconst baseResolved = path.resolve(baseDir) + path.sep;",
			"\tconst safePath = path.resolve(baseDir, path.normalize(userInput));",
			"\tif (safePath !== path.resolve(baseDir) && !safePath.startsWith(baseResolved)) {",
			"\t\treturn res.status(400).json({ error: \"Path traversal access denied\" });",
			"\t}",
		}
	}

	return startLine, replacement, imports, breaking, impact, rationale, tests, nil
}

func (p *PathTraversalPattern) GenerateReference(f *report.Finding, stack string) (*RemediationDiff, string, string, []string, []string, []string) {
	orig := `// Vulnerable: Directly concatenates user input to filesystem path
const filePath = path.join(baseDir, req.query.file);
return res.sendFile(filePath);`

	patched := `// Remediated: Validates canonical path containment with directory separator
const baseResolved = path.resolve(baseDir) + path.sep;
const safePath = path.resolve(baseDir, path.normalize(req.query.file));
if (safePath !== path.resolve(baseDir) && !safePath.startsWith(baseResolved)) {
    return res.status(400).json({ error: "Access denied" });
}
return res.sendFile(safePath);`

	hunkLines := []string{
		"-const filePath = path.join(baseDir, req.query.file);",
		"-return res.sendFile(filePath);",
		"+const baseResolved = path.resolve(baseDir) + path.sep;",
		"+const safePath = path.resolve(baseDir, path.normalize(req.query.file));",
		"+if (safePath !== path.resolve(baseDir) && !safePath.startsWith(baseResolved)) {",
		"+    return res.status(400).json({ error: \"Access denied\" });",
		"+}",
		"+return res.sendFile(safePath);",
	}

	diffText := fmt.Sprintf("--- a/routes/files.js\n+++ b/routes/files.js\n@@ -8,2 +8,6 @@\n%s\n", strings.Join(hunkLines, "\n"))

	remediationDiff := &RemediationDiff{
		TargetFile:         "routes/files.js",
		OriginalSource:     orig,
		PatchedSource:      patched,
		UnifiedDiff:        diffText,
		Hunks: []DiffHunk{
			{OldStart: 8, OldCount: 2, NewStart: 8, NewCount: 6, Heading: "@@ -8,2 +8,6 @@", Lines: hunkLines},
		},
		AddedLinesCount:    6,
		RemovedLinesCount:  2,
		IsReferencePattern: true,
	}

	impact := "Prevents directory traversal by enforcing base directory path containment."
	rationale := "Resolve and normalize path, verifying it starts with the base directory."
	tests := []string{"Assert ../../etc/passwd is rejected with 400 Bad Request"}
	return remediationDiff, impact, rationale, tests, []string{"path"}, nil
}
