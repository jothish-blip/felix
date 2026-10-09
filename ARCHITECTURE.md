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
                                    └───────────────────┘
```

---

## Package Organization & Responsibilities

The codebase is organized into modular packages under `pkg/` and a thin CLI layer under `cmd/`:

| Package | Primary Responsibility | Key Files |
| :--- | :--- | :--- |
| **`cmd/felix`** | CLI parsing, argument validation, subcommand routing, user-facing output formatting. | `main.go`, `scan_cmd.go`, `report_cmd.go`, `config_cmd.go`, `doctor.go`, `version.go`, `completion.go`, `install_cmd.go` |
| **`pkg/crawler`** | Scope enforcement, asset discovery, concurrent downloading, and source map detection. | `crawler.go`, `config.go`, `asset.go`, `scope.go` |
| **`pkg/secrets`** | Pattern detection, Shannon entropy evaluation, placeholder filtering, and secret redaction. | `detector.go`, `patterns.go`, `entropy.go`, `filters.go`, `finding.go` |
| **`pkg/cloud`** | Cloud provider discovery and non-destructive exposure verification (Supabase, Firebase, S3, GCP). | `detector.go`, `provider.go`, `supabase.go`, `firebase.go`, `storage.go`, `client.go`, `finding.go` |
| **`pkg/api`** | Client route extraction, endpoint classification, authentication reasoning, CORS, and header checks. | `detector.go`, `endpoints.go`, `cors.go`, `graphql.go`, `headers.go`, `client.go`, `finding.go` |
| **`pkg/assessment`** | Assessment lifecycle, authorization verification, scope/exclusion engine, embedded SQLite store, and finding traceability. | `models.go`, `scope.go`, `store.go`, `controller.go` |
| **`pkg/report`** | Finding normalization, deduplication, multi-signal correlation, risk scoring, HTML/JSON generation. | `model.go`, `normalize.go`, `dedup.go`, `correlate.go`, `risk.go`, `summary.go`, `html.go`, `json.go` |
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

## Concurrency, Timeouts & Resource Management

Felix implements strict resource controls to ensure safety and prevent denial-of-service impacts against target servers:
- **Worker Concurrency:** Governed by buffered channel semaphores (`chan struct{}` of size `Concurrency`). No unbounded goroutines are created.
- **Timeout Management:** Every network request is bound by `context.WithTimeout` (default: 10s) and propagated into Go's `http.Transport` and `net.Dialer`.
- **Response Size Caps:** All response body reading is bounded by `io.LimitReader(resp.Body, maxBytes+1)`. If an asset exceeds the configured limit, reading aborts immediately with `ErrAssetTooLarge`.
- **Redirect Limits:** Custom `http.Client.CheckRedirect` halts redirection chains after 10 hops to prevent redirect loops.
- **Rate-Limit Backoff:** HTTP `429 Too Many Requests` responses are respected with backoff delays.

---

## Navigation & Cross-References

- **[Operator Usage Guide](USAGE.md)** — Command syntax and flag reference.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Deep dive into verification states and evidence records.
- **[Security & Safety Controls](SECURITY.md)** — Safety boundaries and non-destructive guarantees.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Black-box boundaries and operational limits.
- **[Contributing Guide](CONTRIBUTING.md)** — Development guidelines and regression testing.
