package intelligence

import (
	"strings"
)

// ImplementationStatus represents the operational readiness of a detection engine for a vulnerability class.
type ImplementationStatus string

const (
	StatusImplemented   ImplementationStatus = "IMPLEMENTED"    // Production-grade active or passive verification
	StatusLabTested     ImplementationStatus = "LAB_TESTED"     // Validated against controlled benchmark targets & test fixtures
	StatusMockValidated ImplementationStatus = "MOCK_VALIDATED" // Validated via synthetic fixtures or dry-run mocks
	StatusPlanned       ImplementationStatus = "PLANNED"        // In catalog specification; requires external or future tooling
)

// DetectionStrategy describes the primary approach used to discover and analyze the vulnerability.
type DetectionStrategy string

const (
	StrategyStaticAnalysis     DetectionStrategy = "STATIC_ANALYSIS"
	StrategyDynamicFuzzing      DetectionStrategy = "DYNAMIC_FUZZING"
	StrategyBrowserExecution    DetectionStrategy = "BROWSER_EXECUTION"
	StrategyAPISchemaAnalysis   DetectionStrategy = "API_SCHEMA_ANALYSIS"
	StrategyDifferentialBehavior DetectionStrategy = "DIFFERENTIAL_BEHAVIOR"
	StrategyEntropyHeuristic    DetectionStrategy = "ENTROPY_HEURISTIC"
)

// VulnerabilityClass defines a distinct vulnerability type with its technical and verification characteristics.
type VulnerabilityClass struct {
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	Category           string               `json:"category"`
	OWASP              string               `json:"owasp"`
	CWE                string               `json:"cwe"`
	Severity           string               `json:"severity"`
	Status             ImplementationStatus `json:"status"`
	DetectionStrategy  DetectionStrategy    `json:"detection_strategy"`
	Prerequisites      []string             `json:"prerequisites"`
	ValidationStrategy string               `json:"validation_strategy"`
	KnownLimitations   string               `json:"known_limitations"`
}

// MasterVulnerabilityCatalogue contains the exhaustive centrally maintained vulnerability intelligence catalog.
var MasterVulnerabilityCatalogue = []VulnerabilityClass{
	// 1. INJECTION VULNERABILITIES
	{
		ID:                 "VULN-SQLI-001",
		Name:               "SQL Injection (Error-Based & Boolean-Differential)",
		Category:           "Injection Vulnerabilities",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-89",
		Severity:           "Critical",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Discovered Parameters / Forms", "Unauthenticated or Authenticated"},
		ValidationStrategy: "Dual-canary injection with AST error fingerprinting and Boolean differential response comparison",
		KnownLimitations:   "Dynamic DOM jitter on client SPAs can simulate boolean differences; mitigated via DOM skeleton normalization",
	},
	{
		ID:                 "VULN-NOSQLI-001",
		Name:               "NoSQL Injection ($ne / $gt Operator Injection)",
		Category:           "Injection Vulnerabilities",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-943",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"JSON Body Endpoints", "Unauthenticated or Authenticated"},
		ValidationStrategy: "JSON operator mutation differential comparison against baseline responses",
		KnownLimitations:   "Schema validation middleware rejecting non-string types can preempt execution",
	},
	{
		ID:                 "VULN-CMDI-001",
		Name:               "OS Command Injection",
		Category:           "Injection Vulnerabilities",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-78",
		Severity:           "Critical",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Input Parameters", "Unauthenticated or Authenticated"},
		ValidationStrategy: "Time-delay delta analysis and deterministic command output reflection verification",
		KnownLimitations:   "Blind command execution without network pingback requires controlled OAST listener",
	},
	{
		ID:                 "VULN-SSTI-001",
		Name:               "Server-Side Template Injection (SSTI)",
		Category:           "Injection Vulnerabilities",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-1336",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Reflected Input Parameters"},
		ValidationStrategy: "Mathematical polyglot evaluation (${7*7}, {{7*'7'}}) reflecting exact computed arithmetic result",
		KnownLimitations:   "Sandboxed templating engines (e.g. Jinja2 sandbox) prevent full code execution despite arithmetic evaluation",
	},
	{
		ID:                 "VULN-LDAPI-001",
		Name:               "LDAP Injection",
		Category:           "Injection Vulnerabilities",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-90",
		Severity:           "High",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Authentication Forms", "Directory Lookup Endpoints"},
		ValidationStrategy: "Filter clause wildcard injection producing authentication bypass or differential records",
		KnownLimitations:   "Active directory rate-limiting and account lockout thresholds constrain brute testing",
	},

	// 2. CROSS-SITE SCRIPTING (XSS)
	{
		ID:                 "VULN-XSS-REFLECTED-001",
		Name:               "Reflected Cross-Site Scripting (HTML & Attribute Context)",
		Category:           "Cross-Site Scripting",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-79",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Reflected URL Query / Path Parameters"},
		ValidationStrategy: "Context-aware alphanumeric canary reflection parsing without executing payload",
		KnownLimitations:   "Strict CSP script-src blocks payload execution even when input reflects into the DOM",
	},
	{
		ID:                 "VULN-XSS-DOM-001",
		Name:               "DOM-Based Cross-Site Scripting (Sink Analysis)",
		Category:           "Cross-Site Scripting",
		OWASP:              "A03:2021-Injection",
		CWE:                "CWE-79",
		Severity:           "High",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyBrowserExecution,
		Prerequisites:      []string{"Headless Browser DOM Context", "Client JavaScript Source"},
		ValidationStrategy: "CDP sink hooking (document.write, innerHTML, eval) monitoring canary flow from sources",
		KnownLimitations:   "Heavily obfuscated or minified bundles may conceal data-flow paths between sources and sinks",
	},

	// 3. CROSS-SITE REQUEST FORGERY (CSRF)
	{
		ID:                 "VULN-CSRF-001",
		Name:               "Cross-Site Request Forgery (Missing Anti-CSRF Synchronizer / SameSite: None)",
		Category:           "Cross-Site Request Forgery",
		OWASP:              "A01:2021-Broken Access Control",
		CWE:                "CWE-352",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"State-Changing Endpoints (POST/PUT/DELETE)", "Cookie-Based Authentication"},
		ValidationStrategy: "Execution of state-changing mutation omitting anti-CSRF token or Origin header inspection",
		KnownLimitations:   "Custom Authorization Bearer headers natively mitigate CSRF without requiring CSRF tokens",
	},

	// 4. SERVER-SIDE REQUEST FORGERY (SSRF)
	{
		ID:                 "VULN-SSRF-001",
		Name:               "Server-Side Request Forgery & Cloud Metadata Access",
		Category:           "Server-Side Request Forgery",
		OWASP:              "A10:2021-Server-Side Request Forgery",
		CWE:                "CWE-918",
		Severity:           "Critical",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"URL / Webhook Parameters", "Import Endpoints"},
		ValidationStrategy: "Loopback / Cloud metadata (169.254.169.254) canary injection with safe transport interception",
		KnownLimitations:   "AWS IMDSv2 enforces PUT session tokens, neutralizing simple GET-based SSRF against metadata",
	},

	// 5. BROKEN AUTHENTICATION
	{
		ID:                 "VULN-AUTH-BRUTE-001",
		Name:               "Missing Brute-Force Rate Limiting on Authentication Surface",
		Category:           "Broken Authentication",
		OWASP:              "A07:2021-Identification and Authentication Failures",
		CWE:                "CWE-307",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Login Endpoint URL"},
		ValidationStrategy: "Repeated non-destructive probe burst measuring absence of HTTP 429 Too Many Requests",
		KnownLimitations:   "Upstream CDN/WAF rate limiters may apply globally rather than per-user account",
	},
	{
		ID:                 "VULN-AUTH-JWT-001",
		Name:               "JWT Algorithm Confusion & Weak Signature Controls",
		Category:           "Broken Authentication",
		OWASP:              "A07:2021-Identification and Authentication Failures",
		CWE:                "CWE-1295",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyStaticAnalysis,
		Prerequisites:      []string{"Captured User JWT Token"},
		ValidationStrategy: "Header inspection for alg:none, symmetric HMAC with public key, or unverified signatures",
		KnownLimitations:   "Backend validation cannot be proven definitively without submitting forged tokens to authenticated routes",
	},
	{
		ID:                 "VULN-AUTH-RESET-001",
		Name:               "Insecure Password Reset Token Generation or Leakage",
		Category:           "Broken Authentication",
		OWASP:              "A07:2021-Identification and Authentication Failures",
		CWE:                "CWE-640",
		Severity:           "High",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Password Reset Workflow URL"},
		ValidationStrategy: "Entropy verification of reset tokens and inspection of reset token reflection in response body/headers",
		KnownLimitations:   "Out-of-band email tokens cannot be inspected without inbox integration",
	},

	// 6. BROKEN ACCESS CONTROL & AUTHORIZATION
	{
		ID:                 "VULN-BOLA-001",
		Name:               "Broken Object Level Authorization (BOLA / IDOR)",
		Category:           "BOLA / IDOR",
		OWASP:              "API1:2023-Broken Object Level Authorization",
		CWE:                "CWE-639",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Two Distinct User Identities (User A & User B)", "Object Identifier"},
		ValidationStrategy: "Non-owner session accesses owner's protected object and receives identical protected data",
		KnownLimitations:   "Requires two valid authenticated user identities for cross-tenant or cross-user proof",
	},
	{
		ID:                 "VULN-BFLA-001",
		Name:               "Broken Function Level Authorization (BFLA)",
		Category:           "BFLA",
		OWASP:              "API5:2023-Broken Function Level Authorization",
		CWE:                "CWE-285",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Standard User Token", "Admin Endpoint URL"},
		ValidationStrategy: "Standard unprivileged user session receives HTTP 200 OK on administrative API functions",
		KnownLimitations:   "Requires known administrative route taxonomy or OpenAPI administrative specification",
	},
	{
		ID:                 "VULN-BOPLA-001",
		Name:               "Broken Object Property Level Authorization (Mass Assignment / BOPLA)",
		Category:           "BOPLA",
		OWASP:              "API3:2023-Broken Object Property Level Authorization",
		CWE:                "CWE-915",
		Severity:           "Medium",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Object Mutation Endpoint (PUT/POST/PATCH)", "Authenticated Session"},
		ValidationStrategy: "Injection of privileged fields (is_admin, role, balance) validated through read-back persistence",
		KnownLimitations:   "Read-only excessive property exposure checks require two distinct identities; state-changing mass-assignment mutations require --allow-state-changing --synthetic-fixture against verified isolated fixtures",
	},

	// 7. BUSINESS LOGIC VULNERABILITIES
	{
		ID:                 "VULN-BIZ-PRICE-001",
		Name:               "Business Logic Parameter & Price Tampering",
		Category:           "Business Logic Vulnerabilities",
		OWASP:              "A04:2021-Insecure Design",
		CWE:                "CWE-840",
		Severity:           "High",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Transaction / Checkout Endpoint", "Authenticated Session"},
		ValidationStrategy: "Negative value, zero value, or discounted price mutation accepted in transaction workflow",
		KnownLimitations:   "Production execution prohibited without test merchant gateway configuration",
	},
	{
		ID:                 "VULN-BIZ-STEP-001",
		Name:               "Multi-Step Workflow Step-Skipping",
		Category:           "Business Logic Vulnerabilities",
		OWASP:              "A04:2021-Insecure Design",
		CWE:                "CWE-840",
		Severity:           "Medium",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Multi-Step Workflow (e.g. KYC, Payment -> Confirmation)"},
		ValidationStrategy: "Direct invocation of terminal confirmation step without completing prerequisite intermediate steps",
		KnownLimitations:   "Requires declarative workflow definition or automated workflow graph mapping",
	},

	// 8. SESSION MANAGEMENT WEAKNESSES
	{
		ID:                 "VULN-SESS-COOKIE-001",
		Name:               "Insecure Cookie Flags (Missing HttpOnly, Secure, or SameSite)",
		Category:           "Session Management Weaknesses",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-614",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyStaticAnalysis,
		Prerequisites:      []string{"Set-Cookie Response Headers"},
		ValidationStrategy: "Structural Set-Cookie attribute inspection comparing against HTTPS transport guarantees",
		KnownLimitations:   "None; completely passive and 100% deterministic",
	},
	{
		ID:                 "VULN-SESS-FIXATION-001",
		Name:               "Session Fixation (Identifier Unchanged Across Authentication)",
		Category:           "Session Management Weaknesses",
		OWASP:              "A07:2021-Identification and Authentication Failures",
		CWE:                "CWE-384",
		Severity:           "Medium",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Pre-Auth Session Cookie", "Post-Auth Session Cookie"},
		ValidationStrategy: "Comparison of session cookie token values before and after successful login",
		KnownLimitations:   "Automated login macro required to capture dynamic session transition",
	},

	// 9. API SECURITY VULNERABILITIES
	{
		ID:                 "VULN-API-GRAPHQL-001",
		Name:               "GraphQL Introspection Schema Publicly Exposed",
		Category:           "API Security Vulnerabilities",
		OWASP:              "API8:2023-Security Misconfiguration",
		CWE:                "CWE-200",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyAPISchemaAnalysis,
		Prerequisites:      []string{"GraphQL Endpoint (/graphql)"},
		ValidationStrategy: "Standard __schema introspection query returning full type and query dictionary",
		KnownLimitations:   "Some public APIs intentionally publish introspection for public developer consumption",
	},
	{
		ID:                 "VULN-API-CORS-001",
		Name:               "CORS Wildcard Allowed With Credentials",
		Category:           "API Security Vulnerabilities",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-942",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"HTTP Response Headers"},
		ValidationStrategy: "Arbitrary Origin header reflection accompanied by Access-Control-Allow-Credentials: true",
		KnownLimitations:   "Modern browsers reject origin wildcard with credentials; risk applies primarily to origin reflection",
	},
	{
		ID:                 "VULN-API-METHOD-001",
		Name:               "HTTP Method Tampering & Verb Tunneling",
		Category:           "API Security Vulnerabilities",
		OWASP:              "API8:2023-Security Misconfiguration",
		CWE:                "CWE-650",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDifferentialBehavior,
		Prerequisites:      []string{"Target API Route"},
		ValidationStrategy: "Bypassing GET/POST restrictions via HEAD, OPTIONS, X-HTTP-Method-Override header tunneling",
		KnownLimitations:   "Reverse proxies (NGINX, Envoy) frequently strip override headers before application ingress",
	},

	// 10. INFORMATION DISCLOSURE
	{
		ID:                 "VULN-INFO-DEBUG-001",
		Name:               "Exposed Debug / Telemetry / Health Endpoint",
		Category:           "Information Disclosure",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-489",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Target Base URL"},
		ValidationStrategy: "Detection of exposed /debug, /actuator, /metrics, or /trace routes leaking internal state",
		KnownLimitations:   "Internal IP allowlisting on reverse proxy can return 403 on production perimeters",
	},
	{
		ID:                 "VULN-INFO-STACK-001",
		Name:               "Detailed Error Stack Trace Disclosure",
		Category:           "Information Disclosure",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-209",
		Severity:           "Low",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Input Parameters"},
		ValidationStrategy: "Error trigger (e.g. malformed type, null byte) returning runtime language call stacks in body",
		KnownLimitations:   "Standardized JSON error formats may return exception class names without full code paths",
	},
	{
		ID:                 "VULN-INFO-ENV-001",
		Name:               "Exposed Environment Files (.env, .git, config dumps)",
		Category:           "Information Disclosure",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-552",
		Severity:           "Critical",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Target Web Root"},
		ValidationStrategy: "Direct GET for /.env, /.git/HEAD, /config.json returning valid structure without 404/login redirect",
		KnownLimitations:   "Single-page apps returning index.html for all 404 routes require content-type verification",
	},

	// 11. SECURITY MISCONFIGURATION
	{
		ID:                 "VULN-MISCONF-HEADERS-001",
		Name:               "Missing Defensive Security Headers (CSP, HSTS, XFO, nosniff)",
		Category:           "Security Misconfiguration",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-693",
		Severity:           "Low",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyStaticAnalysis,
		Prerequisites:      []string{"HTTP Response Headers"},
		ValidationStrategy: "Absence or weak syntax of Content-Security-Policy, HSTS, X-Frame-Options, or X-Content-Type-Options",
		KnownLimitations:   "APIs returning pure application/json do not strictly require HTML-specific clickjacking headers",
	},
	{
		ID:                 "VULN-MISCONF-DIR-001",
		Name:               "Directory Indexing / Listing Enabled",
		Category:           "Security Misconfiguration",
		OWASP:              "A05:2021-Security Misconfiguration",
		CWE:                "CWE-548",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Directory Paths (/images/, /static/, /uploads/)"},
		ValidationStrategy: "HTML response containing 'Index of /' or directory listing anchor links",
		KnownLimitations:   "Custom styled directory listings may avoid standard Apache/NGINX signature tokens",
	},

	// 12. FILE UPLOAD VULNERABILITIES
	{
		ID:                 "VULN-UPLOAD-EXT-001",
		Name:               "Unrestricted File Upload / Executable Extension Bypass",
		Category:           "File Upload Vulnerabilities",
		OWASP:              "A04:2021-Insecure Design",
		CWE:                "CWE-434",
		Severity:           "Critical",
		Status:             StatusLabTested,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"Multipart File Upload Endpoint", "Authenticated Session"},
		ValidationStrategy: "Uploading benign polyglot text file with double extension (.php.png, .jsp;.jpg) returning upload success",
		KnownLimitations:   "Storage behind S3/Cloud Storage mitigates server execution unless uploaded file is served via web origin",
	},

	// 13. PATH TRAVERSAL
	{
		ID:                 "VULN-TRAVERSAL-001",
		Name:               "Path Traversal & Arbitrary File Read (LFI)",
		Category:           "Path Traversal",
		OWASP:              "A01:2021-Broken Access Control",
		CWE:                "CWE-22",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyDynamicFuzzing,
		Prerequisites:      []string{"File / Path Query Parameters (e.g. ?file=, ?path=)"},
		ValidationStrategy: "Traversal sequences (../../etc/passwd or ..\\..\\win.ini) matching root OS signature patterns",
		KnownLimitations:   "Chroot jails and containerized scratch images without /etc/passwd yield false negatives",
	},

	// 14. CRYPTOGRAPHIC WEAKNESSES
	{
		ID:                 "VULN-CRYPTO-TLS-001",
		Name:               "Insecure TLS Protocol (TLS 1.0 / 1.1) or Deprecated Ciphers",
		Category:           "Cryptographic Weaknesses",
		OWASP:              "A02:2021-Cryptographic Failures",
		CWE:                "CWE-326",
		Severity:           "Medium",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyStaticAnalysis,
		Prerequisites:      []string{"HTTPS Host:Port"},
		ValidationStrategy: "TLS handshake negotiation asserting TLS 1.2+ minimum and deprecation of CBC/RC4 cipher suites",
		KnownLimitations:   "Requires direct TCP access; CDN termination obscures origin TLS configuration",
	},

	// 15. DEPENDENCY AND KNOWN-CVE EXPOSURE
	{
		ID:                 "VULN-DEP-CVE-001",
		Name:               "Known Vulnerable Software Component / Outdated Dependency CVE",
		Category:           "Dependency and Known-CVE Exposure",
		OWASP:              "A06:2021-Vulnerable and Outdated Components",
		CWE:                "CWE-1395",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyStaticAnalysis,
		Prerequisites:      []string{"Identified Technology & Version", "Local SQLite CVE Database"},
		ValidationStrategy: "SemVer range comparison against indexed National Vulnerability Database & OSV records",
		KnownLimitations:   "Backported security patches on LTS distributions (Debian, RHEL) report vulnerable version without flaw",
	},

	// 16. SENSITIVE DATA AND CREDENTIAL EXPOSURE
	{
		ID:                 "VULN-SECRET-ENTROPY-001",
		Name:               "Exposed Secrets, Private Keys, or High-Entropy API Tokens",
		Category:           "Sensitive Data and Credential Exposure",
		OWASP:              "A07:2021-Identification and Authentication Failures",
		CWE:                "CWE-798",
		Severity:           "High",
		Status:             StatusImplemented,
		DetectionStrategy:  StrategyEntropyHeuristic,
		Prerequisites:      []string{"Client JavaScript Bundles, Manifests, HTML"},
		ValidationStrategy: "Shannon entropy calculation (>3.75) combined with regex alphabet matching and keyword context",
		KnownLimitations:   "High-entropy non-secret hashes (e.g. SHA-256 asset hashes) filtered via structural charset heuristics",
	},
}

// GetMasterCatalogue returns the exhaustive list of all defined vulnerability classes.
func GetMasterCatalogue() []VulnerabilityClass {
	res := make([]VulnerabilityClass, len(MasterVulnerabilityCatalogue))
	copy(res, MasterVulnerabilityCatalogue)
	return res
}

// GetCatalogueCategories returns all distinct category names in the catalog.
func GetCatalogueCategories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, v := range MasterVulnerabilityCatalogue {
		if !seen[v.Category] {
			seen[v.Category] = true
			cats = append(cats, v.Category)
		}
	}
	return cats
}

// FindVulnerabilityByID retrieves a single vulnerability class by its unique ID.
func FindVulnerabilityByID(id string) *VulnerabilityClass {
	clean := strings.ToUpper(strings.TrimSpace(id))
	for _, v := range MasterVulnerabilityCatalogue {
		if strings.EqualFold(v.ID, clean) {
			copyVal := v
			return &copyVal
		}
	}
	return nil
}

// FilterCatalogueByCategory returns all vulnerability classes belonging to a specific category.
func FilterCatalogueByCategory(category string) []VulnerabilityClass {
	var res []VulnerabilityClass
	for _, v := range MasterVulnerabilityCatalogue {
		if strings.EqualFold(v.Category, category) {
			res = append(res, v)
		}
	}
	return res
}
