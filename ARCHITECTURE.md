# Felix Architecture

This document describes the software architecture, operational pipeline, subsystem interactions, and security boundaries implemented in Felix.

---

## High-Level Pipeline

Felix processes targets through a strict, unidirectional analysis pipeline designed to eliminate false positives and enforce non-destructive guarantees:

```text
                  ┌────────────────────────┐
                  │       Target URL       │
                  └───────────┬────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │    Asset & Endpoint Discovery     │  (pkg/crawler)
            │ HTML, JS, CSS, Maps, Routes       │
            └─────────────────┬─────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │        Security Detection         │  (pkg/secrets, pkg/cloud, pkg/api)
            │ Static Signatures, Patterns,      │
            │ Heuristics, Cloud Endpoints       │
            └─────────────────┬─────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │         Safe Verification         │  (pkg/cloud, pkg/api)
            │ Read-Only Probing, CORS Checks,   │
            │ Introspection, Auth Barriers      │
            └─────────────────┬─────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │         Evidence Modeling         │  (pkg/report)
            │ Status Codes, Negative Evidence,  │
            │ Locations, Line Numbers           │
            └─────────────────┬─────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │ Correlation & Risk Prioritization │  (pkg/report)
            │ Deduplication, Security Stories,  │
            │ Deterministic 0–100 Scoring       │
            └─────────────────┬─────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────┐
            │       Reusable Scan Result        │  (JSON in-memory / on-disk)
            └───────────────┬───┬───────────────┘
                            │   │
              ┌─────────────┘   └─────────────┐
              ▼                               ▼
    ┌───────────────────┐           ┌───────────────────┐
    │  Terminal Output  │           │ Offline Reports   │ (Zero Network)
    │  Milestone Status │           │ HTML (Black Mode) │
    └───────────────────┘           │ Sanitized JSON    │
                                    │ SARIF 2.1.0 (CI)  │
                                    └───────────────────┘
```

---

## Package Organization & Responsibilities

The codebase is organized into modular packages under `pkg/` and a thin CLI layer under `cmd/`:

| Package | Primary Responsibility | Key Files |
| :--- | :--- | :--- |
| **`cmd/felix`** | CLI parsing, argument validation, subcommand routing, user-facing output formatting. | `main.go`, `scan_cmd.go`, `report_cmd.go`, `config_cmd.go`, `doctor.go`, `version.go`, `completion.go`, `install_cmd.go` |
| **`pkg/crawler`** | Scope enforcement, static asset discovery, headless browser dynamic SPA discovery, and source maps. | `crawler.go`, `config.go`, `asset.go`, `scope.go`, `browser.go` |
| **`pkg/secrets`** | Pattern detection, Shannon entropy evaluation, placeholder filtering, and secret redaction. | `detector.go`, `patterns.go`, `entropy.go`, `filters.go`, `finding.go` |
| **`pkg/cloud`** | Cloud provider discovery and non-destructive exposure verification (Supabase, Firebase, S3, GCP). | `detector.go`, `provider.go`, `supabase.go`, `firebase.go`, `storage.go`, `client.go`, `finding.go` |
| **`pkg/api`** | Client route extraction, endpoint classification, authentication reasoning, CORS, and header checks. | `detector.go`, `endpoints.go`, `cors.go`, `graphql.go`, `headers.go`, `client.go`, `finding.go` |
| **`pkg/assessment`** | Assessment lifecycle, authorization verification, scope/exclusion engine, embedded SQLite store, and finding traceability. | `models.go`, `scope.go`, `store.go`, `controller.go` |
| **`pkg/discovery`** | Advanced attack-surface intelligence engine: relational graph modeling, domains, applications, APIs, forms, parameters, auth surfaces, cloud services, and passive tech detection. | `types.go`, `domains.go`, `apps.go`, `forms.go`, `parameters.go`, `auth.go`, `tech.go`, `js.go`, `engine.go` |
| **`pkg/auth`** | Authentication intelligence subsystem: multi-signal classification, passive cookie auditing, token structure analysis, protected endpoint reasoning, and zero credential probing. | `types.go`, `classifier.go`, `cookies.go`, `tokens.go`, `protected.go`, `engine.go`, `future_accounts.go` |
| **`pkg/authz`** | Authorization & access control engine: BOLA/IDOR, BFLA, BOPLA, horizontal/vertical privilege escalation, session isolation, and env credential injection. | `types.go`, `session_manager.go`, `planner.go`, `engine.go`, `comparator.go`, `policy.go` |
| **`pkg/apisec`** | OWASP API Security Top 10 (2023) assessment engine: unified evidence-first pipeline, inventory & OpenAPI reconciliation, bounded rate-limit audits, SSRF canary testing, and security misconfiguration analysis. | `types.go`, `inventory.go`, `engine.go` |
| **`pkg/webvuln`** | Web application vulnerability detection and verification: context-aware XSS reflection analysis, SQL injection signatures, SSTI, and SSRF. | `types.go`, `engine.go` |
| **`pkg/sessionsec`** | Session lifecycle, token handling, and identity boundaries (WSTG-SESS/ATHN). | `types.go`, `engine.go` |
| **`pkg/cloudsec`** | Cloud security assessment across AWS, Azure, and GCP (External & Credentialed modes). | `types.go`, `engine.go`, `aws.go`, `azure.go`, `gcp.go` |
| **`pkg/businesslogic`** | Business logic security engine: workflow transition audits, step-skipping, state manipulation, sensitive flow abuse, and replay. | `types.go`, `engine.go`, `analyzer.go` |
| **`pkg/correlation`** | Evidence-driven correlation & attack path engine: multi-signal finding graphs, candidate & verified attack paths, combined risk scoring, and security stories. | `types.go`, `graph.go`, `rules.go`, `engine.go`, `risk.go`, `story.go` |
| **`pkg/verification`** | Verification Engine 2.0: empirical finding verification, dual confidence scoring, safe reproduction generation, safety policy enforcement, and finding trustworthiness. | `types.go`, `confidence.go`, `reproduction.go`, `safety.go`, `policy.go`, `registry.go`, `engine.go` |
| **`pkg/report`** | Finding normalization, deduplication, multi-signal correlation, risk scoring, HTML/JSON/SARIF 2.1.0 generation. | `model.go`, `normalize.go`, `dedup.go`, `correlate.go`, `risk.go`, `summary.go`, `html.go`, `json.go`, `sarif.go` |
| **`pkg/config`** | Persistent operational configuration storage (`~/.felix/config.json`). | `config.go` |
| **`test`** | Integration testing, regression corpus, CLI end-to-end validation, and assessment lifecycle tests. | `regression_test.go`, `cli_test.go`, `assessment_cli_test.go` |

---

## Subsystem Details

### 1. Asset & Endpoint Discovery (`pkg/crawler`)

The crawler acts as the ingestion foundation for all downstream security analysis:
- **Scope Boundary Enforcement:** Before dispatching an HTTP request, target URLs are evaluated against the configured `ScopeMode`:
  - `ScopeSameOrigin`: Permits only the exact scheme, host, and port of the initial target.
  - `ScopeSubdomains`: Permits the root domain and all child subdomains (`*.domain.com`).
  - `ScopeExplicit`: Permits the root domain and an explicitly defined list of allowed hosts.
- **HTML Tokenization:** Uses `golang.org/x/net/html` to parse HTML streams. It discovers:
  - `<script src="...">`: External JavaScript chunks and entrypoints.
  - `<link rel="stylesheet" href="...">`: CSS assets.
  - `<link rel="manifest" href="...">`: Web app manifests.
  - `<base href="...">`: Correct relative URL resolution against declared base targets.
- **Source Map Discovery:** Downloaded JavaScript files are parsed for `//# sourceMappingURL=` comments. If referenced in-scope, source maps are scheduled for download to allow deeper analysis.
- **Dynamic Headless Browser Discovery (`pkg/crawler/browser.go`):**
  - *Zero-Dependency Native Driver:* Uses system Chromium browsers (`msedge`, `chrome`, `chromium`) via CLI headless flags (`--headless=new --dump-dom`), requiring zero Node.js, npm, or Playwright runtime dependencies.
  - *Browser Isolation Safety:* Standard OS browser sandbox protections remain active by default. The isolation-weakening flag `--no-sandbox` is never passed by default and is only available via explicit `DisableSandbox: true` for restricted containerized environments.
  - *DOM Rendering & API Interception:* Evaluates client-side JavaScript within a bounded virtual time budget, discovering dynamically generated links (`<a href="...">`) and runtime API calls (`fetch`, `axios`, `$.ajax`).
  - *Observed vs Inferred Discoveries:* Accurately distinguishes rendered DOM elements (`Inferred: false`) from script string regex heuristics (`Inferred: true`).
  - *Provenance Tagging:* Dynamic discoveries are tagged with `Provenance: PROVENANCE_BROWSER` to preserve complete audit history.
  - *Scope & Redirect Guards:* Enforces strict scope validation before navigation and blocks out-of-scope cross-host redirects.
  - *Graceful Fallback:* If no browser is installed or if the execution times out, the driver reports `Inconclusive: true` and cleanly falls back to static discoveries without aborting the crawl.
- **Resource Limits:**
  - `io.LimitReader`: Streaming reads are capped at `MaxAssetSize` (default: 10MB) to prevent memory exhaustion from oversized assets.
  - `MaxAssets`: Bounded ingestion capping the maximum number of assets processed.

### 2. Secret Intelligence (`pkg/secrets`)

The secret detection engine scans client assets for accidentally committed API keys, tokens, and private credentials:
- **Dual-Engine Detection:**
  1. *Static Signature Matching:* Regular expression patterns matching known vendor key formats (AWS, Stripe, GitHub, Slack, SendGrid, Mailgun, Twilio, OpenAI, Google API, Supabase, Firebase).
  2. *Shannon Entropy Heuristic:* Identifies high-entropy arbitrary strings (> 4.5–5.0 bits/char) in strings of lengths 16–128 characters.
- **False-Positive Suppression:** Evaluates structured alphabets (Hex, Base64, alphanumeric) and eliminates benign artifacts:
  - UUIDs, Git commit SHA hashes, Webpack chunk hashes, CSS colors, test placeholders (`sk_test_...`, `YOUR_KEY_HERE`), and vendor library strings.
- **Static Verification State:** Detected client secrets are assigned `VerificationNotVerified` because client-side static analysis does not test live credential validity against third-party provider APIs.
- **Automatic Redaction:** Raw tokens are never logged or exported in cleartext. Values are systematically masked (e.g. `sb_p****************ud_e`).

### 3. Cloud & BaaS Intelligence (`pkg/cloud`)

Audits cloud backend infrastructure referenced in client assets:
- **Supported Providers:** Supabase, Firebase Realtime Database, AWS S3, Google Cloud Storage.
- **Key Separation Reasoning:** Distinguishes between expected public/anonymous keys (e.g., Supabase `anon` public key) and dangerous administrative keys (e.g., `service_role` secret keys).
- **Non-Destructive Probing:** Executes read-only HTTP GET/HEAD requests to determine whether resources are publicly exposed without authorization:
  - *Supabase:* Bounded GET request to identify whether Row Level Security (RLS) is disabled.
  - *Firebase:* Safe check of `/.json` endpoint for unauthenticated read permissions.
  - *S3 / GCP:* Read-only inspection of bucket permissions.
- **Negative Evidence Recording:** Responses of `401 Unauthorized` or `403 Forbidden` are recorded as affirmative negative evidence proving that access controls are functioning correctly, yielding a `NOT_EXPOSED` verification state.

### 4. API & Application Security Analysis (`pkg/api`)

Analyzes application routes, authorization barriers, and defense-in-depth headers:
- **Client Route Extraction:** Extracts REST paths (`/api/...`, `/v1/...`) and GraphQL endpoints (`/graphql`, `/api/graphql`) from minified JavaScript bundles.
- **Endpoint Taxonomy Classification:** Categorizes endpoints based on URI semantics (`auth`, `admin`, `user`, `payments`, `telemetry`, `debug`, `public`, `unknown`).
- **Authentication-State Reasoning:** Probes discovered endpoints with safe GET/HEAD requests and records status codes:
  - `401 / 403`: Confirms protected authentication boundaries.
  - `200 OK`: Evaluates whether the route is an intended public asset or exposed administrative interface.
  - `308 / 301 / 302`: Identifies unauthenticated client redirects.
  - `404`: Non-existent resource.
- **CORS Policy Analysis:** Submits non-standard test origins (`https://felix.invalid`) to evaluate cross-origin sharing:
  - *Wildcard Origin (`*`):* Permitted for public resources; flagged as `INFO` if credentials are not requested.
  - *Credentialed Reflection (`Access-Control-Allow-Credentials: true`):* Flagged as `HIGH` severity `VERIFIED` exposure if the untrusted test origin is reflected.
- **GraphQL Introspection:** Submits a safe `__schema` query to check if schema introspection is exposed in production.
- **Security Headers:** Inspects presence and configuration of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, and Referrer-Policy.

### 5. Correlation & Risk Scoring (`pkg/report`)

- **Deterministic Deduplication:** Normalizes finding locations, endpoints, and categories to compute unique fingerprints, preventing repetitive findings from cluttering reports.
- **Multi-Signal Security Stories:** Correlates discrete observations into unified attack-path narratives:
  - Example: An exposed Supabase endpoint combined with a leaked `service_role` key and absent RLS triggers an *Exposed Cloud Administrative Capability* story with elevated risk contribution.
- **Deterministic 0–100 Risk Score:**
  - Evaluates verified severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Scales by empirical verification status (`VERIFIED` vs. `NOT_VERIFIED` vs. `OBSERVED`).
  - Subtracts points when negative evidence demonstrates active defenses (`NOT_EXPOSED`).
  - Caps defense-in-depth header findings to a maximum contribution of 20 points.
  - Employs diminishing marginal returns for repetitive lower-tier findings.

---

## Decoupled Scan vs. Report Pipeline

A fundamental design requirement in Felix is the total separation between scanning and reporting:

```text
felix scan <target> --json scan.json
             │
             ├── 1. Performs single network crawl & audit
             ├── 2. Builds unified report in memory
             └── 3. Serializes reusable scan result to disk

felix report scan.json --html report.html
             │
             ├── 1. Reads scan.json from local disk
             ├── 2. Generates self-contained HTML report
             └── 3. Performs ZERO network requests
```

1. **Scan Execution:** `felix scan` performs the audit once, outputs terminal milestones, and writes the canonical `report.Report` struct to disk.
2. **Report Generation:** `felix report` consumes the existing JSON scan result and renders HTML or JSON without initiating network connections, target requests, or external DNS lookups.

---

## Felix 2.0 Assessment Platform Architecture (`pkg/assessment`)

Felix 2.0 transforms Felix from a standalone CLI scanner into a client-aware security assessment platform with persistent end-to-end traceability:

```text
┌──────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│    Client    ├────►│    Authorization     ├────►│    Approved Scope    │
└──────────────┘     └──────────────────────┘     └──────────┬───────────┘
                                                             │
                                                             ▼
┌──────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│    Report    │◄────┤       Finding        │◄────┤ Assessment Execution │
│   Records    │     │   (Linked UUIDs)     │     │      Run Record      │
└──────────────┘     └──────────────────────┘     └──────────────────────┘
```

### 1. Persistence Layer & Storage Design
- **Engine:** Pure-Go embedded SQLite via `modernc.org/sqlite`. Zero external C/C++ dependencies (`CGO_ENABLED=0` cross-compilation across all 5 target operating systems and architectures).
- **Location:** `~/.felix/assessments.db` (overrideable with `FELIX_DIR` environment variable for integration tests).
- **Security:** Directory created with `0700` permissions; database file created with `0600` permissions.
- **Reliability:** Enforces Write-Ahead Logging (`PRAGMA journal_mode = WAL;`), strict foreign key cascade constraints (`PRAGMA foreign_keys = ON;`), and busy timeouts (`5000ms`).
- **Migrations:** Managed versioned schema table (`schema_migrations`) with idempotent DDL migrations.

### 2. Core Relational Schema
- `clients`: ID, Name, Organization, ContactName, ContactEmail, Notes, Timestamps, Archived flag.
- `assessments`: ID, Ref (`ASM-YYYY-XXXX`), ClientID, Name, Description, AssessmentType, Status, ScopeMode, Timestamps, FindingCount.
- `assessment_targets`: ID, AssessmentID, TargetURL, TargetType, ScopeStatus, Label, Timestamps.
- `authorizations`: ID, AssessmentID, AuthorizingParty, AuthorizationMethod, DateReceived, ValidFrom, ValidUntil, ScopeDocRef, InternalNotes, Status.
- `scope_rules`: ID, AssessmentID, RuleType, Pattern, Timestamps.
- `exclusions`: ID, AssessmentID, ExclusionType (`HOSTNAME`, `PATH_PREFIX`, `EXACT_URL`), Pattern, Reason, Timestamps.
- `assessment_executions`: ID, AssessmentID, Status, StartedAt, CompletedAt, DurationMs, RequestCount, ErrorMessage, ConfigSnapshot.
- `assessment_findings`: ID, AssessmentID, ExecutionID, TargetID, OriginalFindingID, Title, Category, Severity, Confidence, VerificationStatus, TargetURL, Endpoint, Method, Fingerprint, Score, EvidenceJSON, VerificationJSON, Remediation, Timestamps.
- `assessment_reports`: ID, AssessmentID, ExecutionID, Format, FilePath, FelixVersion, Status, Timestamps.

### 3. Assessment Lifecycle State Machine
Assessments move through strictly governed transitions:
```text
           ┌──────────┐
           │  DRAFT   │◄────────────────┐
           └────┬─────┘                 │
                │ (authorized)          │ (de-authorize)
                ▼                       │
           ┌──────────┐                 │
           │  READY   ├─────────────────┘
           └────┬─────┘
                │ (felix assessment run)
                ▼
           ┌──────────┐
           │ RUNNING  ├─────────────────────────┐
           └────┬─────┘                         │
                │ (clean completion)            │ (fatal error / crash)
                ▼                               ▼
       ┌─────────────────┐             ┌─────────────────┐
       │    COMPLETED    │             │ FAILED / CANCEL │
       │ (w/ or w/o err) │             └─────────────────┘
       └─────────────────┘
```

### 4. Exclusion Precedence & Redirect Defense
- Exclusions are evaluated **before** checking whether a target or asset is in-scope.
- If a target URL or discovered asset matches an active exclusion (`HOSTNAME`, wildcard `*.subdomain`, `PATH_PREFIX`, or `EXACT_URL`), it is discarded immediately.
- Redirects that escape the approved scope or enter an excluded path are blocked with an immediate security refusal.

---

## Felix 2.0 Stage 2: Advanced Attack-Surface Intelligence (`pkg/discovery`)

Stage 2 transforms Felix's discovery engine from a flat URL crawler into a structured, relational, evidence-backed attack-surface intelligence inventory.

### 1. Relational Inventory Model

Every discovered element is modeled as an `Asset` connected by directed `Relation` graph links:

```text
Domain / Subdomain
   │ (HOSTS)
   ▼
Application
   │
   ├── (EXPOSES_API) ─────────► API Service
   │                               │ (EXPOSES_ENDPOINT)
   │                               ▼
   ├── (EXPOSES_ENDPOINT) ────► Endpoint
   │                               │ (HAS_PARAMETER)
   │                               ▼
   ├── (CONTAINS_FORM) ───────► Form ──► Parameter
   │
   ├── (AUTHENTICATES_TO) ────► Auth Surface (Login, Reset, SSO)
   │
   ├── (USES_TECHNOLOGY) ─────► Technology (Framework, Runtime, CMS)
   │
   ├── (INTEGRATES_WITH) ─────► Cloud Service (S3, Firebase, Supabase)
   │
   └── (LOADS_SCRIPT) ────────► JavaScript Asset
                                   │ (REFERENCES_SOURCE_MAP)
                                   ▼
                                Source Map
```

### 2. Supported Asset & Relation Types

- **14 Asset Types:**
  - `DOMAIN`: Root apex domain (e.g., `example.com`).
  - `SUBDOMAIN`: Discovered hostnames and subdomains (`api.example.com`, `admin.example.com`).
  - `APPLICATION`: Distinct web application or portal root (`/`, `/admin`, `/portal`).
  - `API_SERVICE`: Detected API base (REST, GraphQL, versioned routes).
  - `ENDPOINT`: Concrete HTTP path with method (`GET /api/v1/users`).
  - `PARAMETER`: Discovered query parameter, path variable, form input, or JSON key.
  - `FORM`: Statically parsed HTML `<form>` element.
  - `AUTH_SURFACE`: Dedicated authentication gateway (Login, Register, MFA, Password Reset, SSO).
  - `CLOUD_SERVICE`: Cloud storage bucket or BaaS backend (S3, GCP, Supabase, Firebase).
  - `TECHNOLOGY`: Detected technology, library, framework, or web server.
  - `SOURCE_MAP`: Bound or discovered JavaScript source map.
  - `DATA_ASSET`: Static data document, download, or configuration schema.
  - `NETWORK_HOST`: Resolved IP address for a host.
  - `THIRD_PARTY_SERVICE`: External dependency or CDN host.

- **12 Relation Types:**
  - `CONTAINS`: Domain contains Subdomain or Application.
  - `HOSTS`: Host serves Application or API Service.
  - `EXPOSES_API`: Application exposes API Service.
  - `EXPOSES_ENDPOINT`: Application or API exposes specific Endpoint.
  - `HAS_PARAMETER`: Endpoint or Form accepts Parameter.
  - `CONTAINS_FORM`: Application or Endpoint contains HTML Form.
  - `USES_TECHNOLOGY`: Application or Host runs Technology.
  - `DEPENDS_ON`: Asset depends on external Service.
  - `AUTHENTICATES_TO`: Application routes through Auth Surface.
  - `INTEGRATES_WITH`: Application integrates with Cloud Service.
  - `LOADS_SCRIPT`: Application loads JavaScript Asset.
  - `REFERENCES_SOURCE_MAP`: JavaScript asset points to Source Map.

### 3. Specialized Intelligence Extractors

1. **Domain & Subdomain Intelligence (`domains.go`):**
   - Extracts apex domains using strict public suffix heuristics (handling dual suffixes like `.co.uk`).
   - Parses hostnames from HTML markup, script tags, stylesheets, and anchors.
   - Extracts Subject Alternative Names (SAN) from TLS certificates when available without additional network round-trips.
   - Performs safe DNS A/AAAA resolution (`net.LookupIP`) to identify network IPs.
   - Strictly tags third-party or out-of-scope hostnames (`InScope = false`, `DiscoveryStatus = OUT_OF_SCOPE`).

2. **Application Intelligence (`apps.go`):**
   - Identifies root and sub-applications (`/admin`, `/portal`, `/app`, `/api`).
   - Detects SPA routing mechanisms (React Router, Next.js, Nuxt, Angular, Vue).

3. **Form Intelligence (`forms.go`):**
   - Statically parses HTML `<form>` elements and nested controls (`<input>`, `<textarea>`, `<select>`).
   - Normalizes action URLs, HTTP methods (default `GET`), and encoding types (`application/x-www-form-urlencoded`, `multipart/form-data`).
   - Classifies form purpose (`LOGIN`, `REGISTRATION`, `PASSWORD_RESET`, `FILE_UPLOAD`, `SEARCH`).
   - **Zero Form Submission Guarantee:** Verified by tests with `atomic.LoadInt64(&formSubmissionCount) == 0`. Forms are parsed purely for structural intelligence.

4. **Parameter Intelligence (`parameters.go`):**
   - Extracts query parameters from crawled URLs and templates.
   - Normalizes path segment parameters (`/api/v1/users/{id}`).
   - Captures form inputs and static JavaScript payload keys.
   - Records parameter locations (`QUERY`, `PATH`, `BODY_FORM`, `BODY_JSON`, `HEADER`, `COOKIE`) and inferred data types (`INTEGER`, `UUID`, `STRING`, `BOOLEAN`).

5. **Authentication Surface Intelligence (`auth.go`):**
   - Discovers login forms, registration endpoints, password resets, MFA gateways, OAuth/OIDC redirects, session cookies, and logout paths.
   - Extracts OAuth/OIDC client IDs and scopes from markup and client scripts.
   - **Zero Credential Probing Policy:** Authentication entrypoints are mapped defensively; no password spraying, credential stuffing, or session brute-forcing is executed.

6. **Technology Intelligence (`tech.go`):**
   - Passive signature engine evaluating HTTP response headers (`Server`, `X-Powered-By`), cookies, and DOM markup.
   - Detects Web Servers (Nginx, Apache), Frameworks (Express, Django, Laravel, Rails, ASP.NET, Next.js, Nuxt), CMS (WordPress, Drupal), and UI Libraries (React, Vue, Angular, Tailwind, Bootstrap).
   - Extracts version numbers when present; distinguishes observed versions (`version_observed = true`) from unverified estimates.

7. **JavaScript Static Intelligence (`js.go`):**
   - Safe static regex/lexical analysis without code execution or browser DOM rendering.
   - Extracts API routes, base URLs, WebSocket endpoints (`ws://`, `wss://`), cloud references, and environment variable references.
   - Inspects bounded source map references (`//# sourceMappingURL=`).
   - Masks all detected secret candidates (`[REDACTED_SECRET]`) in evidence.

### 4. Database Schema Migration v2

Stage 2 applies Migration `2` to `~/.felix/assessments.db`:
- `assessment_inventory_assets`: Persistent table storing assets with canonical SHA-256 fingerprint deduplication, type, display name, in-scope flag, status, confidence, structured metadata JSON, evidence JSON, and observation timestamps.
- `assessment_inventory_relations`: Persistent directed graph table linking `source_asset_id` to `target_asset_id` with `relation_type`, evidence, and confidence.
- Foreign keys cascade-delete inventory records when an assessment is removed. Indexed on `(assessment_id, asset_type)` and `(assessment_id, canonical_id)` for high-performance querying.

### 5. Authentication Intelligence Subsystem (`pkg/auth`)

Stage 3 introduces a dedicated, evidence-driven authentication intelligence subsystem:
- **Multi-Signal Classification (`classifier.go`):** Identifies and classifies authentication entrypoints across 10 categories (Login, Registration, Password Reset, MFA, Session, Cookies, Tokens, Auth State, Alternative Paths, Protected Endpoints) using route heuristics, form attributes, parameter combinations, and client SDK signatures (Supabase GoTrue, Firebase Auth, NextAuth, Clerk, Auth0, WebAuthn).
- **Passive Cookie Security Inspection (`cookies.go`):** Parses Set-Cookie response headers without storing sensitive cookie values. Audits defensive attributes (`Secure`, `HttpOnly`, `SameSite`), determines functional purpose (`SESSION`, `CSRF`, `PREFERENCE`, `TRACKING`), and flags security defects directly into report findings.
- **Token Artifact Inspection (`tokens.go`):** Detects token parameters and patterns across client assets. Safely parses unverified JWT headers to extract declared algorithms (flagging `alg=none`), checks OAuth PKCE configurations (flagging `plain` challenge methods), and extracts OAuth/recovery tokens with zero credential replay.
- **Empirical Protected Endpoint Reasoning (`protected.go`):** Assesses access protection based on empirical HTTP responses (401 with `WWW-Authenticate` challenges, 403 Forbidden, 302/307 redirects to login, 200 anonymous accessible).
- **Database Schema Migration v3:**
  - `assessment_auth_surfaces`: Stores classified authentication surfaces with category, subtype, canonical ID, confidence, auth state, and evidence.
  - `assessment_auth_cookies`: Records cookie metadata, security flags, and defect lists (zero secret value persistence).
  - `assessment_auth_tokens`: Stores token structure observations, algorithm declarations, and locations.
### 6. Authorization & Access Control Intelligence (`pkg/authz`)

Stage 4 introduces a dedicated, evidence-driven API authorization testing engine that evaluates server-side permission enforcement across five primary vulnerability categories:
- **Broken Object Level Authorization (BOLA / IDOR):** Models multi-identity object access (Identity A owns Object A, Identity B owns Object B). Detects when Identity B can read or operate on Object A without authorization, distinguishing legitimately shared resources and application-level denial bodies from genuine unauthorized disclosure.
- **Broken Function Level Authorization (BFLA):** Tests administrative and privileged operations against unprivileged user identities. Verifies whether restricted management endpoints (e.g., user deletion, tenant export) are enforced server-side rather than hidden client-side.
- **Broken Object Property Level Authorization (BOPLA):**
  - **Property Exposure:** Detects unauthorized exposure of sensitive internal properties (e.g., `role`, `credit_score`, `price`, `internal_id`) to unprivileged users.
  - **Property Modification:** Evaluates unauthorized attempts to mutate server-controlled fields (e.g., attempting `{"role": "admin"}` or `{"price": 0.00}`).
  - **Write Test Safety Guard:** Enforces `policy.allow_write_tests == true` before sending any mutating HTTP requests (`PUT`, `POST`, `PATCH`, `DELETE`). If false, mutating tests are safely refused and reported as candidates with zero destructive network activity.
- **Horizontal Privilege Escalation:** Verifies tenant and peer isolation boundaries when users of equivalent privilege levels attempt cross-access.
- **Vertical Privilege Escalation:** Detects when an unprivileged user performs an operation or assumes privileges reserved for administrative roles.
- **Multi-Identity Session Manager (`session_manager.go`):**
  - *Isolated Cookie Jars:* Maintains dedicated `http.Client` instances with separate `cookiejar.Jar`s per identity alias. Session cookies set for `user_a` never leak or cross-contaminate requests made on behalf of `user_b`.
  - *Runtime Environment Credential Injection:* Supports injecting tokens and session cookies via environment variables (`FELIX_AUTH_<ALIAS>_TOKEN`, `FELIX_AUTH_<ALIAS>_COOKIE`, `FELIX_AUTH_<ALIAS>_HEADER_<KEY>`), allowing sensitive test credentials to be supplied securely at runtime without committing secrets to policy files (see verified sample template in `examples/authz_policy_sample.json`).
  - *Pre-Flight Session Validation:* Verifies each identity's baseline access prior to comparative differential testing. If an identity's session returns HTTP 401 or 403 on its own resource, tests involving that identity are classified as `BLOCKED_INVALID_SESSION`, preventing false positive BOLA findings and false negatives.
- **Deep Comparator (`comparator.go`):** Evaluates HTTP status codes, body payloads, resource identifiers, and ownership markers. Never treats HTTP status codes alone as proof of authorization correctness or vulnerability.
- **Secret Redaction Across Storage & Output:** All sensitive tokens (`Authorization: Bearer [REDACTED]`, cookie values, sensitive query parameters, and private response fields) are scrubbed end-to-end. Raw credentials are never persisted in SQLite or displayed in reports.
- **Database Schema Migration v4:**
  - `assessment_authz_policies`: Stores sanitized assessment permission policies and authorization document references.
  - `assessment_authz_results`: Records test case executions, observed vs baseline status codes, empirical evidence summaries, redacted request/response snippets, and finding associations.

### 7. OWASP API Security Engine (`pkg/apisec`)

Stage 5 introduces a first-class, evidence-driven API security testing engine systematically addressing all ten categories of the **OWASP API Security Top 10 (2023)**:
- **API1:2023 — Broken Object Level Authorization (BOLA / IDOR):** Maps empirical findings from the Stage 4 authorization engine (`pkg/authz`) and performs passive route analysis for endpoints containing resource identifiers (`/users/{id}`, UUIDs). If no authorization policy is provided, reports entry points with `PREREQUISITE_MISSING`.
- **API2:2023 — Broken Authentication:** Audits session cookie defensive flags (`Secure`, `HttpOnly`, `SameSite`), token structures, unverified JWT header algorithms (flagging `alg=none`), and unauthenticated identity surfaces discovered via Stage 3 (`pkg/auth`).
- **API3:2023 — Broken Object Property Level Authorization (BOPLA):** Evaluates unauthorized object property exposure and mutation attempts from Stage 4, distinguishing excessive data exposure from mass-assignment vulnerability.
- **API4:2023 — Unrestricted Resource Consumption:** Conducts safe, bounded probes (maximum 3 requests) to verify rate-limiting telemetry headers (`RateLimit-Limit`, `RateLimit-Remaining`, `Retry-After`) and analyzes pagination limits (`limit`, `pageSize`, `per_page`). Zero denial-of-service load is generated.
- **API5:2023 — Broken Function Level Authorization (BFLA):** Evaluates administrative role boundaries and unprivileged function execution from Stage 4, or passively inventories exposed management routes (`/admin`, `/manage`).
- **API6:2023 — Unrestricted Access to Sensitive Business Flows:** Discovers and categorizes business workflows (`USER_REGISTRATION`, `CHECKOUT_TRANSACTION`, `PASSWORD_RESET`, `INVITATION_REFERRAL`) to audit for anti-automation, rate limiting, and abuse mitigations without executing simulated transactions.
- **API7:2023 — Server-Side Request Forgery (SSRF):** Identifies remote URL-fetching parameters (`url`, `dest`, `webhook`, `callback`). Probes only an explicitly approved, non-internal canary callback URL. Probing localhost, 127.0.0.1, AWS/GCP cloud metadata (`169.254.169.254`), or private RFC 1918 subnets is strictly blocked by `isInternalAddress` guards.
- **API8:2023 — Security Misconfiguration:** Audits missing `X-Content-Type-Options: nosniff` headers, overly permissive CORS wildcards (`Access-Control-Allow-Origin: *`), and verbose backend error/stack trace disclosures.
- **API9:2023 — Improper Inventory Management:** Compares discovered attack-surface endpoints against client-supplied OpenAPI/Swagger JSON or line-delimited route specifications to detect undocumented "Shadow APIs", and flags concurrent exposure of multiple API versions (e.g., `v1` alongside `v2`).
- **API10:2023 — Unsafe Consumption of APIs:** Audits external third-party integration points (Stripe, Twilio, GitHub, Google) referenced in assets, evaluating downstream trust boundaries without interacting with third-party infrastructure.
- **Database Schema Migration v5:**
  - `assessment_apisec_runs`: Stores overall run metrics, total tests executed, categories covered, verified counts, candidate counts, and full category coverage JSON.
  - `assessment_apisec_results`: Records granular test evaluations, OWASP category codes, verification states (`VERIFIED`, `CANDIDATE`, `OBSERVED`, `NOT_VULNERABLE`), severity, confidence, observed HTTP statuses, evidence summaries, and sanitized finding linkages.

### 8. Verification Engine 2.0 (`pkg/verification`)

Stage 11 introduces Verification Engine 2.0 to provide commercial-grade empirical evidence verification, dual confidence scoring, deterministic reproduction steps, and finding trustworthiness across all assessment engines.

- **Fundamental Principle:** A detection is a hypothesis until sufficient empirical evidence establishes what actually occurred. A finding never becomes `VERIFIED` through high detection confidence, pattern presence, or severity alone.
- **Canonical Verification States:**
  - `OBSERVED`: Target asset, surface, or artifact was noted without asserting an active vulnerability or security weakness (e.g., exposed public landing page).
  - `DETECTED`: Static or heuristic indicator identified, but active empirical verification was not executed, is pending, or is precluded by lack of credentials.
  - `NOT_VERIFIED`: Verification was attempted, but evidence was inconclusive, prerequisite configurations were absent, or affirmative proof could not be obtained.
  - `VERIFIED`: Deterministic, empirical, reproducible proof obtained meeting all vulnerability-specific mandatory criteria.
  - `NOT_EXPOSED`: Confirmed negative evidence demonstrating affirmative denial (e.g. `401 Unauthorized` / `403 Forbidden` access barrier) or validated boundary defenses.
- **Dual Confidence Scoring Model (`confidence.go`):**
  - **Detection Confidence (0–40 points):** Measures static pattern clarity, entropy, and heuristic indicators.
  - **Verification Confidence (0–60 points):** Measures empirical proof, passing criteria, and affirmative verification.
  - **Dual Invariants:** High detection confidence alone is strictly capped at `ConfidenceMedium` (score ≤ 40). A finding cannot attain `VERIFIED` status without passing all mandatory criteria. Contradictory evidence triggers severe confidence penalties. Synthetic test fixtures are explicitly tracked and labeled (`[SYNTHETIC FIXTURE]`).
- **Specialized Verification Policies (`policy.go`, `registry.go`):**
  - `POL-DISC-01` (Discovery & Exposure): Distinguishes observed assets, unverified secrets in client code, and affirmative 401/403 access denials (`NOT_EXPOSED`) from confirmed leaks (`VERIFIED`).
  - `POL-AUTH-01` (Authentication & Identity): Verifies defensive cookie attributes (`HttpOnly`, `Secure`, `SameSite`) and unauthenticated access; records access barriers as `NOT_EXPOSED`.
  - `POL-AUTHZ-01` (Authorization & Access Control): Enforces differential comparative access proof between authorized and unauthorized identities; single-request checks without control comparisons fail to `NOT_VERIFIED`.
  - `POL-APISEC-01` (API Security): Audits excessive data exposure by verifying sensitive payload fields, and audits missing security headers via response header inspection.
  - `POL-WEBVULN-01` (Web Vulnerabilities): Reflected strings alone are not XSS (requires unescaped execution context); generic 500 errors alone are not SQLi (requires concrete database error signature); 404s are not path traversal.
  - `POL-CLOUD-01` (Cloud Infrastructure): Distinguishes anonymous bucket listing (`VERIFIED`) from access denial (`NOT_EXPOSED`) and unverified cloud references (`NOT_VERIFIED`).
  - `POL-BIZLOGIC-01` (Business Logic): Requires before/after state transition proof; state-changing checks blocked by default without write authorization.
  - `POL-GENERIC-01` (Generic Fallback): Fallback policy for unclassified findings, safely defaulting to `NOT_VERIFIED`.
- **Safety Boundaries (`safety.go`):**
  - Scope and origin boundary validation.
  - Excluded paths and hostnames take absolute precedence.
  - Non-destructive execution: mutating/state-changing probes (`POST`, `PUT`, `DELETE`) are blocked unless explicitly authorized, falling back to read-only audits.
  - Per-target request quotas prevent accidental stress on target servers.
- **Deterministic Reproduction & Secret Redaction (`reproduction.go`):**
  - Generates human-readable reproduction steps and safe, copy-pasteable `curl` commands.
  - Redacts authorization tokens, bearer tokens, API keys, passwords, and sensitive cookies (`[REDACTED]`).
- **Database Schema Migration v11 (`store.go`):**
  - `assessment_verification_runs`: Persists verification run metrics, attempted counts, verified counts, detected counts, not verified counts, not exposed counts, blocked counts, inconclusive counts, synthetic counts, and verifier version (`2.0.0`).
  - `assessment_verification_results`: Persists finding verification results, target URL, endpoint, category, verification status, policy ID, verification method, confidence score, criteria results JSON, reproduction JSON, and timestamps.

### 9. Commercial Report 2.0 (`pkg/report`)

Stage 12 implements Commercial Report 2.0, transforming raw assessment findings, empirical verification results, correlation chains, attack paths, and evidence provenance into an executive-ready, client-facing deliverable without conducting new network activity.

- **Strict Reporting & Presentation Layer:**
  - Zero new security probes or active checks.
  - Zero mutation of underlying source findings or risk scores.
  - No synthetic asset or evidence fabrication.
  - Deterministic serialization regardless of finding input order.
- **Strict Exclusion of Remediation Advice:**
  - Remediation instructions, root cause fixes, remediation prioritization, and fix validation are strictly excluded from Commercial Report 2.0 and reserved for Stage 13 Remediation Intelligence 3.0.
  - Generic recommendations (e.g., "enable MFA", "update packages", "restrict access") are prohibited.
  - Finding impact is presented strictly through demonstrated vs plausible vs unverified security consequences without prescribing mitigations.
- **Eight Canonical Report Sections:**
  1. **Executive Summary:** Overall completion status, target scope, discovery count, verified vs detected counts, posture narrative, and scope limitations. Empty assessments explicitly state that zero verified findings does not prove the target is entirely secure.
  2. **Assessment Scope:** In-scope domains, URL boundaries, assessed endpoint count, evaluated authentication identities, executed engines, and explicit exclusions/restrictions.
  3. **Attack Surface:** Catalog of all discovered assets (routes, static bundles, APIs, forms, cloud endpoints) across crawling, API inspection, secret detection, and cloud modules. Asset presence never implies exploitability.
  4. **Risk Overview:** Felix 0–100 deterministic risk score meter, correlated attack paths (candidate vs verified), risk concentrations by component, and verified vs detected severity breakdown.
  5. **Verified Findings:** Strictly reserved for findings with canonical verification status `VERIFIED`. Formatted according to the 10-field specification (A–J).
  6. **Detected Findings:** Unverified detection hypotheses, including `DETECTED`, `NOT_VERIFIED`, and inconclusive/blocked checks. Never conflated with verified vulnerabilities.
  7. **Observations:** Informational signals (`OBSERVED`), asset inventory items, and defensive configurations that do not assert a security weakness.
  8. **Technical Appendix:** Complete auditable appendix containing:
     - Negative verification outcomes (`NOT_EXPOSED` defensive boundary confirmations).
     - End-to-end finding traceability index (source, fingerprint, policy, engine).
     - Engine execution records and synthetic fixture indicators (`[SYNTHETIC FIXTURE]`).
- **Standardized Finding Model (10 Fields A–J):**
  - **A. Description:** Objective summary of the condition with secrets redacted.
  - **B. Affected Asset & Location:** Target endpoint and line/DOM/parameter location.
  - **C. Severity:** Standardized tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNAVAILABLE`).
  - **D. Confidence:** Dual detection confidence and verification confidence ratings preserved distinctly.
  - **E. Authentication State:** Explicit state (`Unauthenticated`, `Authenticated`, `Privileged`, `Multiple Identities`, `Unknown`, `Not Applicable`).
  - **F. Detection Method:** Technique used (`active_probe`, `static_pattern_signature`, `header_inspection`, etc.).
  - **G. Verification:** Canonical status, policy ID, satisfied criteria, missing criteria, preconditions, and testing limitations.
  - **H. Evidence:** Sanitized excerpts, HTTP status/method, headers, safe reproduction curl commands, provenance (`LIVE`, `STATIC`, `FIXTURE`), and timestamp.
  - **I. Security Impact:** Demonstrated impact, plausible secondary impact, and unverified bounds (no remediation).
  - **J. Risk Contribution:** Source finding score, individual vs correlated vs attack-path contribution, with zero double-counting.
- **Defensive Boundary Handling (`NOT_EXPOSED`):**
  - Confirmed access barriers (HTTP 401/403) and negative proof are classified as `NOT_EXPOSED` and routed exclusively to the Technical Appendix.
  - `NOT_EXPOSED` findings contribute 0 to the risk score and are never displayed in the Verified Findings section.
- **CI/CD SARIF 2.1.0 Integration (`pkg/report/sarif.go`):**
  - *Standard Compliance:* Generates schema-valid OASIS SARIF 2.1.0 JSON exports directly ingestible by GitHub Code Scanning, GitLab Security Dashboard, and Azure DevOps.
  - *Rule Deduplication:* Normalizes and deduplicates finding categories into deterministic `tool.driver.rules` with stable indexing.
  - *Severity Mapping:* Maps Felix severities (`CRITICAL`/`HIGH` $\rightarrow$ `error`, `MEDIUM` $\rightarrow$ `warning`, `LOW` $\rightarrow$ `note`, `INFO` $\rightarrow$ `none`).
  - *Accurate Locations:* Uses `logicalLocations` (`GET /api/v1/orders/{id}`) without fabricating fake source code line numbers when evaluating black-box HTTP targets.
  - *Full Property Bag:* Preserves Felix empirical metadata (`verification_status`, `confidence`, `provenance`, `safe_reproduction`, `score`) in result properties.
  - *Secret Scrubbing:* Recursively redacts tokens and sensitive data before serialization.

---

## Stage 13: Felix Operator Console & Curation Engine

Stage 13 introduces **Felix Operator**: a local-first management interface and finding curation engine that bridges raw security execution with client-facing commercial reporting and delivery tracking.

```
Clients → Assessments → Targets & Scope → Scan Execution → Findings & Evidence
                                                                   ↓
Reports Delivery Tracking ← Commercial Report 2.0 ← Finding Review Curation
                                                     (Approved / Rejected / Pending)
```

### Core Architecture & Invariants
1. **Local-First, Strict Loopback Binding (`127.0.0.1`):**
   - Designed strictly as an internal operator tool, never a multi-tenant or public SaaS.
   - Binds exclusively to loopback addresses (`127.0.0.1` or `::1`). Any attempt to bind to external or wildcard interfaces (`0.0.0.0`) is actively blocked with a security refusal error.
2. **Cryptographic Token & CSRF Origin Enforcement:**
   - On startup, the server generates a cryptographically random 32-byte hex operator token (`X-Felix-Operator-Token` header / `Authorization: Bearer`).
   - For all mutating state changes (`POST`, `PUT`, `DELETE`, `PATCH`), the server validates the `Origin` (and fallback `Referer`) against trusted loopback origins. Cross-origin mutations and permissive CORS are strictly prohibited.
3. **Editorial vs Technical Verification Invariant:**
   - Operator finding review decisions (`APPROVED_FOR_REPORT`, `REJECTED`, `PENDING`) are stored exclusively in the `finding_reviews` table.
   - **Crucial Invariant:** An operator review decision *never* mutates, overrides, or alters the underlying finding's technical `VerificationStatus`, confidence score, raw HTTP evidence, or provenance.
4. **Curated Commercial Report Generation:**
   - Only findings explicitly reviewed and marked `APPROVED_FOR_REPORT` are included in finalized Commercial Report 2.0 deliverables.
   - Unreviewed findings (`PENDING`) block final report compilation to ensure commercial quality, failing closed unless explicitly requested as a labeled `[DRAFT - PENDING REVIEW]` deliverable.
   - Rejected findings (`REJECTED`) are completely excluded from commercial reports, attack paths, and risk score calculations.
5. **Report Delivery Handover Tracking:**
   - Formal client handover tracking (`report_deliveries`) is maintained independently from report compilation.
   - Supports delivery methods (`ENCRYPTED_EMAIL`, `SECURE_DOWNLOAD`, `CLIENT_PORTAL`, `IN_PERSON`) with delivery timestamps only recorded when verified.
6. **SQLite Scan Leases & Append-Only Audit Logging (Database Schema Migration v12):**
   - Migration `12` in `store.go` establishes operator persistence: `finding_reviews`, `report_deliveries`, `scan_job_leases`, and `operator_audit_events`.
   - Background execution mutual exclusion is managed via SQLite leases (`scan_job_leases`) with heartbeat tracking, preventing duplicate concurrent scans on the same assessment across processes or restarts.
   - All state-changing operator activities (client creation, authorization, target scoping, scans, reviews, report generation, deliveries) are immutably recorded in `operator_audit_events`.
7. **Single Binary Distribution (`embed.FS`):**
   - The web console UI (`pkg/operator/web/`) is embedded directly into the Go executable via `embed.FS`. Zero Node.js, npm, or external web server dependencies are required.

---

## Concurrency, Timeouts & Resource Management

Felix implements strict resource controls to ensure safety and prevent denial-of-service impacts against target servers:
- **Worker Concurrency:** Governed by buffered channel semaphores (`chan struct{}` of size `Concurrency`). No unbounded goroutines are created.
- **Timeout Management:** Every network request is bound by `context.WithTimeout` (default: 10s) and propagated into Go's `http.Transport` and `net.Dialer`.
- **Response Size Caps:** All response body reading is bounded by `io.LimitReader(resp.Body, maxBytes+1)`. If an asset exceeds the configured limit, reading aborts immediately with `ErrAssetTooLarge`.
- **Redirect Limits:** Custom `http.Client.CheckRedirect` halts redirection chains after 10 hops to prevent redirect loops.
- **Rate-Limit Handling:** HTTP `429 Too Many Requests` responses fail fast with `ErrRateLimited` rather than silently blocking worker goroutines with sleep backoffs. For rate-sensitive targets, use `--concurrency 1`.

---

## Navigation & Cross-References

- **[Operator Usage Guide](USAGE.md)** — Command syntax and flag reference.
- **[Author Learning Guide](LEARNING.md)** — 10 progressive study modules covering architecture, discovery, verification, authz, correlation, risk, and extensions.
- **[Validation Matrix](VALIDATION-MATRIX.md)** — Source-grounded capability matrix, test coverage, and non-goals.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Deep dive into verification states and evidence records.
- **[Security & Safety Controls](SECURITY.md)** — Safety boundaries and non-destructive guarantees.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Black-box boundaries and operational limits.
- **[Contributing Guide](CONTRIBUTING.md)** — Development guidelines and regression testing.
