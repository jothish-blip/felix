# Felix Architecture & Author Learning Guide

This guide is designed for developers, security engineers, and assessment operators who want to understand, audit, maintain, and safely extend the **Felix Cybersecurity Assessment Engine**.

Felix is architected as a single-binary, pure Go engine with **zero external runtime dependencies** (no Node.js driver, no Python, no external database server). It enforces non-destructive, evidence-driven security assessment across web applications, APIs, cloud environments, and business logic workflows.

---

## Pedagogical Roadmap

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Module 1: Architecture, Pipeline Overview & CLI Entry Point            │
├────────────────────────────────────────────────────────────────────────┤
│ Module 2: Scope Boundaries, Target Governance & Crawler Discovery      │
├────────────────────────────────────────────────────────────────────────┤
│ Module 3: Detection vs Empirical Verification Contracts                │
├────────────────────────────────────────────────────────────────────────┤
│ Module 4: Authorization Intelligence & Multi-Role Session Isolation    │
├────────────────────────────────────────────────────────────────────────┤
│ Module 5: Correlation Engine & Evidence-Driven Attack Paths            │
├────────────────────────────────────────────────────────────────────────┤
│ Module 6: Combined Risk Modeling & Threat Prioritization               │
├────────────────────────────────────────────────────────────────────────┤
│ Module 7: Commercial Reporting & CI/CD SARIF 2.1.0 Integration         │
├────────────────────────────────────────────────────────────────────────┤
│ Module 8: Evidence Invariants, Provenance & Secret Sanitization        │
├────────────────────────────────────────────────────────────────────────┤
│ Module 9: Persistence, Audit Trails & Migration History                │
├────────────────────────────────────────────────────────────────────────┤
│ Module 10: Safe Extension Guide & Assessor Discipline                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Module 1: Architecture, Pipeline Overview & CLI Entry Point

### 1. Problem Statement
Security tools frequently devolve into spaghetti scripts with scattered entry points, inconsistent argument parsing, and uncoordinated network activities. Felix requires a centralized CLI router, deterministic configuration lifecycle, and a strict unidirectional pipeline:
$$\text{Discovery} \longrightarrow \text{Detection} \longrightarrow \text{Verification} \longrightarrow \text{Evidence} \longrightarrow \text{Correlation} \longrightarrow \text{Risk} \longrightarrow \text{Report}$$

### 2. Key Files & Symbols
- [`cmd/felix/main.go`](cmd/felix/main.go): Main CLI router, banner printing, and exit code handling.
- [`cmd/felix/scan_cmd.go`](cmd/felix/scan_cmd.go): Subcommand handler for `felix scan` and standalone audit pipelines.
- [`cmd/felix/assessment_cmd.go`](cmd/felix/assessment_cmd.go): Assessment workflow runner for managed assessment runs (`felix assessment`).
- [`cmd/felix/report_cmd.go`](cmd/felix/report_cmd.go): Zero-network reporting runner (`felix report`).
- [`pkg/config/config.go`](pkg/config/config.go): Persistent local configuration storage and defaults.

### 3. Data Flow & Execution Path
1. The operator invokes `felix` with subcommands (`scan`, `assessment`, `report`, `operator`, `doctor`, `version`).
2. `main()` inspects `os.Args[1]`, parses global flags, and dispatches to the corresponding subcommand runner.
3. If executing `scan`, `runScan()` initializes the configuration, parses target URLs or file inputs, validates scope arguments, and executes the audit pipeline sequentially.
4. If executing `report`, `runReport()` loads an existing JSON scan result from disk and performs **zero network requests**, generating HTML, JSON, or SARIF 2.1.0 deliverables.

### 4. Reading Order
1. [`cmd/felix/main.go`](cmd/felix/main.go)
2. [`cmd/felix/scan_cmd.go`](cmd/felix/scan_cmd.go)
3. [`cmd/felix/report_cmd.go`](cmd/felix/report_cmd.go)
4. [`cmd/felix/assessment_cmd.go`](cmd/felix/assessment_cmd.go)

### 5. Comprehension Questions
1. Why does `felix report` enforce a zero-network invariant, and what security benefits does this provide during client report generation?
2. What are the three standard exit codes returned by Felix CLI commands, and how do they map to CI/CD pass/fail gates?
3. How does `cmd/felix/scan_cmd.go` avoid panics when handling SIGINT or SIGTERM interruptions?

### 6. Practical Exercises
- **Exercise 1.1:** Build the Felix CLI locally using `go build -o bin/felix.exe ./cmd/felix` and verify version and health diagnostics with `./bin/felix.exe version` and `./bin/felix.exe doctor`.
- **Exercise 1.2:** Trace the argument parser in `cmd/felix/scan_cmd.go` to see how `--export report.html,scan.sarif` handles multiple export targets simultaneously.

---

## Module 2: Scope Boundaries, Target Governance & Crawler Discovery

### 2.1 Problem Statement
Web crawling without strict scope boundaries risks unintended requests against third-party systems, OAuth providers, or unapproved infrastructure. Furthermore, modern Single Page Applications (SPAs) render navigation links and API endpoints dynamically via JavaScript, which cannot be discovered by static HTML regex scrapers alone.

### 2.2 Key Files & Symbols
- [`pkg/crawler/scope.go`](pkg/crawler/scope.go): `Scope`, `ScopeMode` (`ScopeSameOrigin`, `ScopeSubdomains`, `ScopeExplicit`), and host filtering.
- [`pkg/crawler/crawler.go`](pkg/crawler/crawler.go): `Crawler`, `Crawl()`, `downloadAsset()`, `parseHTMLAssets()`, and concurrency semaphores.
- [`pkg/crawler/asset.go`](pkg/crawler/asset.go): `Asset`, `AssetType`, `ClassifyAsset()`, `ExtractSourceMapURL()`, and asset provenance constants.
- [`pkg/crawler/browser.go`](pkg/crawler/browser.go): `BrowserDiscoveryDriver`, `HeadlessBrowserDriver`, `ExtractDynamicEndpoints()`, and `FindBrowserBinary()`.

### 2.3 Data Flow & Execution Path
1. `NewScope()` normalizes target URLs and configures allowed domains and host boundaries.
2. In Phase 1, `Crawler.Crawl()` fetches the base HTML, parses tags (`<script>`, `<link>`, `<form>`, `<a>`), resolves relative URLs, and downloads in-scope assets concurrently using a worker pool.
3. In Phase 2, JavaScript assets are inspected for `sourceMappingURL` references, and discovered source maps are ingested.
4. In Phase 3, if dynamic browser discovery is enabled (`BrowserDiscovery.Enabled`), `BrowserDiscoveryDriver` launches a bounded headless browser session with OS sandbox protections active by default (`--headless=new --dump-dom`), executes JavaScript, extracts DOM-injected routes and runtime API calls (`fetch`, `axios`), distinguishes observed DOM elements (`Inferred: false`) from script regex heuristics (`Inferred: true`), and tags discoveries with `ProvenanceBrowser` while blocking out-of-scope navigations.

### 2.4 Reading Order
1. [`pkg/crawler/scope.go`](pkg/crawler/scope.go)
2. [`pkg/crawler/asset.go`](pkg/crawler/asset.go)
3. [`pkg/crawler/crawler.go`](pkg/crawler/crawler.go)
4. [`pkg/crawler/browser.go`](pkg/crawler/browser.go)

### 2.5 Comprehension Questions
1. How does `scopedClientForTarget()` in `pkg/crawler/crawler.go` prevent HTTP redirect hops from leaking requests to out-of-scope domains?
2. What happens when no supported headless browser binary is installed on the assessor's operating system?
3. Why are dynamic browser discoveries explicitly tagged with `PROVENANCE_BROWSER` instead of merging invisibly into static discoveries?

### 2.6 Practical Exercises
- **Exercise 2.1:** Inspect [`pkg/crawler/browser_test.go`](pkg/crawler/browser_test.go) and run `go test -v -run TestBrowserDiscovery_JSRenderedRoute ./pkg/crawler` to trace how DOM-rendered links are discovered and extracted.
- **Exercise 2.2:** Write a test case demonstrating that an external tracking link (e.g. `https://analytics.external.com`) discovered inside a JavaScript bundle is assigned `InScope: false` and never downloaded.

---

## Module 3: Detection vs Empirical Verification Contracts

### 3.1 Problem Statement
The primary failure mode of automated security scanners is equating pattern matching with confirmed vulnerability. A regex match on a string `AKIA...` or an API path `/admin/users` does NOT prove vulnerability or exposure. Felix enforces a mandatory distinction between:
- **Observed:** An asset, endpoint, or configuration was seen to exist.
- **Detected:** A heuristic, pattern, or signature flagged a potential risk.
- **Verified:** Active, non-destructive empirical probing proved the vulnerability exists under tested conditions.
- **Not Verified:** Verification was attempted but empirical proof was not obtained.
- **Not Exposed:** Negative-verification proof confirmed that the claimed exposure was absent (e.g. valid authentication barrier enforced, endpoint returning HTTP 404).

### 3.2 Key Files & Symbols
- [`pkg/verification/types.go`](pkg/verification/types.go): `VerificationRecord`, `VerificationStatus`, `ProvenanceType`, `VerificationClaim`.
- [`pkg/verification/engine.go`](pkg/verification/engine.go): `Engine`, `Verify()`, and verification policy orchestrator.
- [`pkg/verification/policy.go`](pkg/verification/policy.go): Specific verification policies and criteria for cloud, web, and secrets.
- [`pkg/verification/confidence.go`](pkg/verification/confidence.go): Confidence calculation combining signal strength, empirical proof, and negative evidence.
- [`pkg/webvuln/engine.go`](pkg/webvuln/engine.go): Safe web vulnerability detection and verification (CORS, security headers, GraphQL, open redirects).
- [`pkg/cloud/cloud.go`](pkg/cloud/cloud.go): Safe cloud provider endpoint verification (Supabase, Firebase, AWS S3 buckets).

### 3.3 Data Flow & Execution Path
1. A detection engine (`pkg/secrets`, `pkg/cloud`, `pkg/webvuln`) identifies a candidate finding.
2. The finding is passed to `verification.Engine.Verify()`.
3. The engine looks up the claim-specific verification policy in `pkg/verification/policy.go`.
4. A read-only verification probe is executed within safety bounds.
5. The response status, headers, and body are evaluated against claim-specific criteria:
   - Status 200 with data exposure $\rightarrow$ `VERIFIED`.
   - Status 401/403 with authentication barrier enforced $\rightarrow$ `NOT_EXPOSED` (when claim asserted public exposure).
   - Ambiguous or error responses $\rightarrow$ `NOT_VERIFIED` or `INCONCLUSIVE`.
6. A `VerificationRecord` is generated with rationale, safe reproduction steps, and empirical proof.

### 3.4 Reading Order
1. [`pkg/verification/types.go`](pkg/verification/types.go)
2. [`pkg/verification/policy.go`](pkg/verification/policy.go)
3. [`pkg/verification/engine.go`](pkg/verification/engine.go)
4. [`pkg/verification/confidence.go`](pkg/verification/confidence.go)

### 3.5 Comprehension Questions
1. Why does Felix forbid blanket mappings of HTTP 401/403 directly to `NOT_EXPOSED` without claim-specific context?
2. What is the difference between `NOT_VERIFIED` and `NOT_EXPOSED`?
3. How does `SyntheticFixture` tracking prevent mock test data from being confused with live production verification in client reports?

### 3.6 Practical Exercises
- **Exercise 3.1:** Run `go test -v -run TestMatrix ./pkg/report` and inspect the 18 verification matrix tests validating distinct empirical transitions.
- **Exercise 3.2:** Modify a mock response in `pkg/verification/verification_test.go` from HTTP 403 to HTTP 500 and verify that the classification transitions from `NOT_EXPOSED` to `NOT_VERIFIED`.

---

## Module 4: Authorization Intelligence & Multi-Role Session Isolation

### 4.1 Problem Statement
Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA) cannot be discovered by single-user crawlers. Authorization testing requires simulating multiple distinct identities (`user_a`, `user_b`, `admin`) and performing comparative differential testing. However, naive implementations suffer from session state pollution (cookie leaks across roles) and false BOLA alerts caused by expired sessions.

### 4.2 Key Files & Symbols
- [`pkg/authz/types.go`](pkg/authz/types.go): `AuthzPolicy`, `TestIdentity`, `TestResource`, `EndpointRule`, `AuthzTestCase`, `AuthzTestResult`.
- [`pkg/authz/session_manager.go`](pkg/authz/session_manager.go): `SessionManager`, `GetClientForIdentity()`, `InjectEnvCredentials()`, and `VerifyIdentitySession()`.
- [`pkg/authz/planner.go`](pkg/authz/planner.go): `Planner`, `PlanTestCases()`, BOLA/BFLA/BOPLA matrix planning.
- [`pkg/authz/comparator.go`](pkg/authz/comparator.go): `Comparator`, `Compare()`, differential response comparison.
- [`pkg/authz/engine.go`](pkg/authz/engine.go): `Engine`, `Execute()`, baseline cache, and safety guard enforcement.

### 4.3 Data Flow & Execution Path
1. Assessor provides an `AuthzPolicy` JSON file defining test identities (`user_a`, `user_b`), resources, and endpoint rules.
2. `InjectEnvCredentials()` checks environment variables (`FELIX_AUTH_<ALIAS>_TOKEN`, `FELIX_AUTH_<ALIAS>_COOKIE`) and populates runtime credentials securely without committing secrets.
3. `SessionManager` allocates independent `http.Client` instances with separate `cookiejar.Jar`s per identity alias.
4. `Planner.PlanTestCases()` creates baseline (`ALLOW`) test cases and cross-identity (`DENY`) test cases.
5. In Step 1, baseline cases run to establish ground truth. If an identity receives HTTP 401/403 on its own resource, its session is flagged as invalid.
6. In Step 2, test cases run against the baseline. If an identity's session was invalid, tests are marked `BLOCKED_INVALID_SESSION` rather than asserting false findings. If an unauthorized identity receives HTTP 200 with matching resource data, BOLA is verified.

### 4.4 Reading Order
1. [`pkg/authz/types.go`](pkg/authz/types.go)
2. [`pkg/authz/policy.go`](pkg/authz/policy.go) & [`examples/authz_policy_sample.json`](examples/authz_policy_sample.json)
3. [`pkg/authz/session_manager.go`](pkg/authz/session_manager.go)
4. [`pkg/authz/planner.go`](pkg/authz/planner.go)
5. [`pkg/authz/comparator.go`](pkg/authz/comparator.go)
6. [`pkg/authz/engine.go`](pkg/authz/engine.go)

### 4.5 Comprehension Questions
1. How does `SessionManager` ensure that session cookies received by Alice are never transmitted in requests sent on behalf of Bob?
2. What role does the `allow_write_tests` policy flag play in preventing accidental state mutations during authorization audits?
3. Why does an expired session on a baseline check produce `BLOCKED_INVALID_SESSION` instead of `VERIFIED` or `NOT_VULNERABLE`?

### 4.6 Practical Exercises
- **Exercise 4.1:** Run `go test -v -run TestSessionManager ./pkg/authz` and trace the cookie isolation and environment variable injection tests.
- **Exercise 4.2:** Inspect the verified sample policy at [`examples/authz_policy_sample.json`](examples/authz_policy_sample.json) and run `go test -v -run TestLoadPolicyFromFile_SamplePolicy ./pkg/authz` to observe policy validation and environment variable injection.

---

## Module 5: Correlation Engine & Evidence-Driven Attack Paths

### 5.1 Problem Statement
Individual vulnerability scanners produce fragmented, unranked finding lists. In real-world security incidents, attackers chain multiple minor exposures (e.g. exposed JavaScript bundle $\rightarrow$ leaked API key $\rightarrow$ unauthenticated database $\rightarrow$ horizontal privilege escalation) into catastrophic attack paths. Felix's correlation engine models this causality explicitly without inventing hypothetical connections.

### 5.2 Key Files & Symbols
- [`pkg/correlation/types.go`](pkg/correlation/types.go): `AttackNode`, `AttackEdge`, `AttackPath`, `SecurityStory`, `CorrelationRule`.
- [`pkg/correlation/engine.go`](pkg/correlation/engine.go): `Engine`, `BuildGraph()`, `FindAttackPaths()`, graph traversal algorithms.
- [`pkg/correlation/rules.go`](pkg/correlation/rules.go): Built-in correlation rules linking secrets, cloud endpoints, APIs, and authorization flaws.
- [`pkg/correlation/story.go`](pkg/correlation/story.go): `SecurityStory` generator synthesizing executive summaries and investigate-first guidance.

### 5.3 Data Flow & Execution Path
1. Normalized assessment findings from all engines are converted into graph `AttackNode`s.
2. The correlation engine applies registered rules (`pkg/correlation/rules.go`) to discover relationships between nodes (e.g. `EXPOSES`, `AUTHENTICATES`, `ESCALATES_TO`).
3. Directed acyclic graphs (DAGs) of plausible attack trajectories are traced from initial entry points to terminal impact assets.
4. Each discovered path is synthesized into an evidence-backed `AttackPath` and `SecurityStory`.
5. Missing evidence and unverified assumptions are explicitly recorded in `MissingEvidence` and `Assumptions` fields.

### 5.4 Reading Order
1. [`pkg/correlation/types.go`](pkg/correlation/types.go)
2. [`pkg/correlation/rules.go`](pkg/correlation/rules.go)
3. [`pkg/correlation/engine.go`](pkg/correlation/engine.go)
4. [`pkg/correlation/story.go`](pkg/correlation/story.go)

### 5.5 Comprehension Questions
1. What prevents the correlation engine from generating false security stories when individual findings lack empirical relationships?
2. How are candidate attack paths distinguished from verified attack paths in report presentation?
3. What is the role of `InvestigateFirst` in a generated `SecurityStory`?

### 5.6 Practical Exercises
- **Exercise 5.1:** Inspect `pkg/correlation/correlation_test.go` and trace how a leaked Firebase token is correlated with an exposed Firebase database endpoint.
- **Exercise 5.2:** Run `go test -v -run TestSecurityStory ./pkg/correlation` to observe how multi-finding security stories are generated and formatted.

---

## Module 6: Combined Risk Modeling & Threat Prioritization

### 6.1 Problem Statement
Scoring individual vulnerabilities in isolation using static CVSS scores fails to reflect true business risk. A low-severity information disclosure on a public static asset is trivial, but the exact same disclosure providing credentials to a critical database creates existential risk. Felix implements a deterministic, multi-factor risk model.

### 6.2 Key Files & Symbols
- [`pkg/correlation/risk.go`](pkg/correlation/risk.go): `CalculatePathRisk()`, `CombinedRiskLevel`, combined risk scoring algorithm.
- [`pkg/report/risk.go`](pkg/report/risk.go): Target-level risk scoring (0–100), severity weights, and priority ranking.
- [`pkg/report/severity.go`](pkg/report/severity.go): Standard severity definitions (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

### 6.3 Data Flow & Execution Path
1. Path risk combines:
   - Node severity scores along the attack path.
   - Empirical verification status (verified paths score higher than unverified candidates).
   - Asset criticality and terminal impact severity.
2. Deduplication safeguards ensure that multiple correlated findings in a single story do not artificially inflate the target's overall risk score through double-counting.
3. The overall assessment risk score is clamped deterministically between 0 and 100.

### 6.4 Reading Order
1. [`pkg/report/severity.go`](pkg/report/severity.go)
2. [`pkg/report/risk.go`](pkg/report/risk.go)
3. [`pkg/correlation/risk.go`](pkg/correlation/risk.go)

### 6.5 Comprehension Questions
1. How does the combined risk algorithm penalize attack paths that rely on unverified assumptions?
2. Why is risk scoring guaranteed to be deterministic across repeated executions?
3. How does Felix prevent double-counting when five findings participate in the same attack path?

### 6.6 Practical Exercises
- **Exercise 6.1:** Run `go test -v -run TestRiskScoring ./pkg/report` and observe how severity counts map to final risk scores.
- **Exercise 6.2:** Trace `CalculatePathRisk()` in `pkg/correlation/risk.go` to see the exact mathematical weight given to `VerificationVerified` vs `VerificationDetected`.

---

## Module 7: Commercial Reporting & CI/CD SARIF 2.1.0 Integration

### 7.1 Problem Statement
Audit findings must serve two disparate audiences:
1. Executive leadership and technical teams requiring clear, client-ready commercial reports without alarmist speculation or unverified claims.
2. Automated CI/CD pipelines requiring standardized, machine-readable SARIF 2.1.0 exports to populate GitHub Code Scanning, GitLab SAST/DAST dashboards, and Azure DevOps security tabs.

### 7.2 Key Files & Symbols
- [`pkg/report/model.go`](pkg/report/model.go): Core `Report` and `Finding` models.
- [`pkg/report/commercial_model.go`](pkg/report/commercial_model.go): Commercial Report 2.0 specification (Executive Summary, Scope, Attack Surface, Risk Overview, Verified Findings, Detected Findings, Observations, Appendix).
- [`pkg/report/commercial_builder.go`](pkg/report/commercial_builder.go): `BuildCommercialReport()`, section compilation.
- [`pkg/report/commercial_html.go`](pkg/report/commercial_html.go): High-contrast, client-ready HTML report renderer.
- [`pkg/report/sarif.go`](pkg/report/sarif.go): OASIS SARIF 2.1.0 exporter, rule deduplication, property bags, and severity mapping.

### 7.3 Data Flow & Execution Path
1. `BuildCommercialReport()` transforms raw assessment data into the eight canonical commercial sections.
2. Findings are segregated strictly by verification state: verified findings appear in Section 5, unverified detections in Section 6, and baseline signals in Section 7.
3. `BuildSARIFLog()` translates findings into SARIF 2.1.0 format:
   - Rules are extracted and deduplicated into `tool.driver.rules`.
   - Severity maps to standard SARIF levels (`error`, `warning`, `note`, `none`).
   - Logical locations store API endpoints (`GET /api/v1/orders`) without fabricating fake source line numbers.
   - Property bags retain Felix-specific verification status, confidence, score, and provenance.
4. Outputs are saved via `WriteHTML()`, `WriteJSON()`, or `WriteSARIF()`.

### 7.4 Reading Order
1. [`pkg/report/commercial_model.go`](pkg/report/commercial_model.go)
2. [`pkg/report/commercial_builder.go`](pkg/report/commercial_builder.go)
3. [`pkg/report/sarif.go`](pkg/report/sarif.go)
4. [`cmd/felix/report_cmd.go`](cmd/felix/report_cmd.go)

### 7.5 Comprehension Questions
1. Why does Commercial Report 2.0 strictly separate Verified Findings from Detected Findings?
2. What are the SARIF level equivalents for Felix `CRITICAL`, `MEDIUM`, and `LOW` severities?
3. Why does Felix SARIF export use `logicalLocations` instead of fabricating fake source code line numbers when auditing black-box HTTP endpoints?

### 7.6 Practical Exercises
- **Exercise 7.1:** Run `go test -v -run TestSARIF ./pkg/report` to inspect schema validation, rule deduplication, and secret scrubbing in SARIF exports.
- **Exercise 7.2:** Export an audit report to SARIF format using `./bin/felix.exe scan https://example.com --sarif audit.sarif --quiet` and inspect the generated JSON structure.

---

## Module 8: Evidence Invariants, Provenance & Secret Sanitization

### 8.1 Problem Statement
Security assessment reports must provide irrefutable technical evidence (HTTP status, headers, response snippets, safe reproduction commands). However, unredacted reports risk leaking the very credentials, JWTs, and private keys they were meant to protect. Furthermore, assessors must always know whether evidence originated from a live target, a static file, or a synthetic test fixture.

### 8.2 Key Files & Symbols
- [`pkg/report/json.go`](pkg/report/json.go): `SanitizeEvidence()`, `SanitizeReport()`, automated credential scrubbing.
- [`pkg/authz/types.go`](pkg/authz/types.go): `RedactText()`, `RedactBody()`, `RedactRequestSummary()`, PEM/JWT/cookie regex scrubbers.
- [`pkg/verification/types.go`](pkg/verification/types.go): `ProvenanceType` (`LIVE`, `STATIC`, `FIXTURE`, `MOCK`, `IMPORTED`).

### 8.3 Data Flow & Execution Path
1. During assessment, raw HTTP responses and requests are captured.
2. Prior to persistence or report generation, all strings, headers, and bodies pass through recursive sanitizers.
3. Bearer tokens, passwords, cookies, and private key blocks are replaced with `[REDACTED]` or `[REDACTED_JWT]`.
4. The provenance of every observation is permanently recorded and passed through to the final deliverable.

### 8.4 Reading Order
1. [`pkg/report/json.go`](pkg/report/json.go)
2. [`pkg/report/sarif.go`](pkg/report/sarif.go) & [`.github/workflows/felix-audit.yml`](.github/workflows/felix-audit.yml)
3. [`pkg/authz/types.go`](pkg/authz/types.go) (Lines 180–375)
4. [`pkg/verification/types.go`](pkg/verification/types.go)

### 8.5 Comprehension Questions
1. How does `RedactBody()` handle structured JSON responses versus free-form unstructured text?
2. Why is provenance tracking critical when presenting verification results to client stakeholders?
3. What regex patterns are used in `pkg/report/json.go` to intercept and redact JWT tokens?

### 8.6 Practical Exercises
- **Exercise 8.1:** Run `go test -v -run TestSecretRedaction ./pkg/report` and `go test -v -run TestSecretRedaction_EndToEnd ./pkg/authz`.
- **Exercise 8.2:** Run `go test -v -run TestSARIF ./pkg/report` and inspect [`.github/workflows/felix-audit.yml`](.github/workflows/felix-audit.yml) to see how SARIF 2.1.0 exports integrate into CI/CD security quality gates.

---

## Module 9: Persistence, Audit Trails & Migration History

### 9.1 Problem Statement
Enterprise assessments require reliable local-first persistence, transactional integrity, and complete auditability. Felix uses pure Go SQLite (`modernc.org/sqlite`) with zero external database processes, managing forward-only schema migrations across stages.

### 9.2 Key Files & Symbols
- [`pkg/assessment/store.go`](pkg/assessment/store.go): `Store`, SQLite connection management, and CRUD operations.
- [`pkg/assessment/migrations.go`](pkg/assessment/migrations.go): Schema migrations v1 through v10.
- Database Tables:
  - `assessments`, `targets`, `scans`, `findings`
  - `verification_records`, `correlation_graphs`, `attack_paths`, `security_stories`
  - `operator_reviews`, `operator_audit_events`, `report_deliveries`

### 9.3 Data Flow & Execution Path
1. `NewStore()` opens the local SQLite database file (e.g. `%LOCALAPPDATA%\Felix\felix.db`).
2. `Migrate()` executes any unapplied migration scripts sequentially within a database transaction.
3. Every operator review decision, scan execution, and report delivery creates an immutable record in `operator_audit_events`.
4. Crucial Invariant: Operator editorial decisions (`APPROVED_FOR_REPORT`, `REJECTED`) control report visibility only; they **never mutate or overwrite** the technical finding's verification status, raw evidence, or provenance.

### 9.4 Reading Order
1. [`pkg/assessment/migrations.go`](pkg/assessment/migrations.go)
2. [`pkg/assessment/store.go`](pkg/assessment/store.go)

### 9.5 Comprehension Questions
1. How does Felix ensure zero external database server dependencies while supporting concurrent reads?
2. What happens if a database migration fails midway through execution?
3. Why is the operator audit event log designed as append-only?

### 9.6 Practical Exercises
- **Exercise 9.1:** Run `go test -v ./pkg/assessment` to verify all migrations and database transactions.
- **Exercise 9.2:** Inspect the schema definition for migration v10 in `pkg/assessment/migrations.go` and trace the correlation tables.

---

## Module 10: Safe Extension Guide & Assessor Discipline

### 10.1 Problem Statement
When extending a cybersecurity assessment engine, developer enthusiasm often leads to aggressive active payloads, out-of-scope traffic, third-party dependency bloat, and broken verification contracts. Extension authors must follow strict architectural discipline.

### 10.2 Architectural Invariants (Must Never Be Broken)
1. **Zero External Runtime Dependencies:** Never import packages requiring CGO, external shared libraries, Python, Node.js, or external database servers. Felix must compile into a standalone binary.
2. **Non-Destructive Safety Guarantee:** Never implement destructive payloads (e.g. `DROP TABLE`, filesystem writes, account takeovers, brute force flooding). Probes must be read-only or harmless.
3. **Evidence-Driven Verification:** Never label a finding `VERIFIED` based on a pattern match or HTTP status code alone. Verification requires concrete, claim-specific empirical proof.
4. **Scope Strictness:** Every outbound HTTP request must be validated against `Scope.IsAllowed()` and checked against exclusions. Cross-host redirect hops must be caught and blocked.
5. **Secret Redaction:** Never emit raw credentials, tokens, or session keys in reports, logs, or SARIF output. Always route through `SanitizeEvidence()` / `RedactText()`.

### 10.3 Step-by-Step Guide: Adding a New Verification Rule
1. **Define the Finding Type:** Add the canonical category and title in the appropriate package.
2. **Implement Safe Detection:** Implement the heuristic or pattern detector in `pkg/webvuln`, `pkg/cloud`, or `pkg/secrets`.
3. **Author Verification Policy:** Add a dedicated verification policy in `pkg/verification/policy.go` defining exact positive proof criteria and negative proof criteria.
4. **Add Unit & Fixture Tests:** Create controlled local HTTP fixture tests in the test suite covering both positive (vulnerable) and negative (secure/not exposed) scenarios.
5. **Wire into Report Normalization:** Verify that `pkg/report/normalize.go` and `pkg/report/sarif.go` correctly map the new category and severity.
6. **Verify End-to-End:** Run `go test -count=1 ./...` and `go vet ./...`.

### 10.4 Comprehension Questions
1. Why is active brute-forcing explicitly prohibited in Felix assessment modules?
2. How does an extension author verify that a new rule does not violate scope redirect restrictions?
3. What steps are required to ensure a new finding category appears correctly in both HTML reports and SARIF 2.1.0 exports?

### 10.5 Practical Exercises
- **Exercise 10.1:** Walk through the implementation of `TestMatrix10_GraphQLIntrospectionSucceeds_Verified` in `pkg/report/report_test.go` as a gold-standard reference for a verification test case.
- **Exercise 10.2:** Review `CONTRIBUTING.md` and verify that any proposed changes meet all architectural invariants.
