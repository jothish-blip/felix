# Felix

> Black-Box Web Security Auditing CLI  
> *"Attackers rely on luck. Felix leaves them zero."*

Felix is an authorized, defensive black-box web security auditing CLI written in Go. It operates via modular engines to systematically ingest, analyze, and assess web application attack surfaces.

---

## Architecture

```text
felix/
├── cmd/
│   └── felix/
│       └── main.go            # CLI entrypoint & formatted output
├── pkg/
│   ├── crawler/               # Engine 1: Asset Ingestion
│   │   ├── asset.go           # Asset model, classification & source map detection
│   │   ├── config.go          # Engine configuration & defaults
│   │   ├── crawler.go         # Core crawler pipeline & concurrent worker pool
│   │   ├── crawler_test.go    # Test suite (unit & mock HTTP integration tests)
│   │   └── scope.go           # Origin & host scope boundary enforcement
│   │
│   ├── secrets/               # Engine 2: Secret Intelligence
│   │   ├── detector.go        # Scanner orchestration & context evaluation
│   │   ├── patterns.go        # Signature registry & JWT inspector
│   │   ├── entropy.go         # Shannon entropy calculation
│   │   ├── finding.go         # Secret finding model & redaction
│   │   ├── filters.go         # False positive & placeholder filtering
│   │   └── detector_test.go   # Engine 2 test suite
│   │
│   ├── cloud/                 # Engine 3: Cloud & BaaS Intelligence
│   │   ├── provider.go        # Provider enums & service models
│   │   ├── detector.go        # Provider discovery & verification coordinator
│   │   ├── finding.go         # Cloud finding model & deduplication
│   │   ├── supabase.go        # Supabase RLS auditor & key separation
│   │   ├── firebase.go        # Firebase Realtime Database auditor
│   │   ├── storage.go         # AWS S3 & GCP Cloud Storage auditor
│   │   ├── client.go          # Bounded HTTP probe client
│   │   └── cloud_test.go      # Engine 3 test suite
│   │
│   ├── api/                   # Engine 4: Modern API & Endpoint Auditor
│   │   ├── finding.go         # API finding model & redaction
│   │   ├── client.go          # Bounded probe client with scope protection
│   │   ├── graphql.go         # Safe GraphQL introspection auditor
│   │   ├── cors.go            # Conservative CORS origin reflection auditor
│   │   ├── endpoints.go       # Sensitive endpoint auditor (.env, .git, metrics)
│   │   ├── headers.go         # Defensive security headers auditor
│   │   ├── detector.go        # Engine 4 coordinator & endpoint discovery
│   │   └── api_test.go        # Engine 4 test suite
│   │
│   └── report/                # Engine 5: Correlation, Risk & Reporting
│       ├── model.go           # Unified finding & report models
│       ├── normalize.go       # URL, method, severity & category normalization
│       ├── dedup.go           # Deterministic finding deduplication
│       ├── correlate.go       # Multi-engine finding correlation & security stories
│       ├── risk.go            # Felix Risk Score (0-100) scoring model
│       ├── severity.go        # Explainable severity ratings & rankings
│       ├── summary.go         # Summarization & deterministic prioritization
│       ├── html.go            # Self-contained offline HTML report generator
│       ├── json.go            # Machine-readable sanitized JSON exporter
│       └── report_test.go     # Engine 5 test suite
│
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

---

## Engine 1 — Felix Crawler (Asset Ingestion)

Engine 1 serves as the safe asset discovery and collection pipeline:

```text
Target URL
    ↓
Scope Validation
    ↓
HTTP Request
    ↓
HTML Parsing
    ↓
Asset Discovery (Scripts, Stylesheets, Manifests)
    ↓
URL Normalization
    ↓
Deduplication
    ↓
Worker Pool (Bounded Concurrency)
    ↓
Asset Download (Subject to Scope & Response Limits)
    ↓
Response Validation (Status Codes, Timeouts)
    ↓
Size Limits (Max Asset Size Enforcement)
    ↓
Asset Classification (MIME & Extension Analysis)
    ↓
Source Map Detection (//# sourceMappingURL Extraction)
    ↓
Asset Inventory ([]Asset)
```

### Key Capabilities

- **Asset Ingestion Model (`Asset`)**: Fully decoupled data structure storing asset URL, type (`javascript`, `stylesheet`, `manifest`, `source-map`), raw content, status codes, and size.
- **Concurrent Worker Pool**: Bounded goroutines with semaphore-controlled concurrency.
- **Strict Scope Boundaries**: Default same-origin enforcement prevents unauthorized cross-origin requests while recording discovered external references.
- **Memory & Response Safety**: Configurable maximum asset size limit (default 10 MB) via bounded `io.LimitReader` stream reads.
- **Source Map Discovery**: Automatic discovery and relative resolution of `//# sourceMappingURL=...` declarations in JavaScript bundles.
- **Hardened HTTP Client**: Connection pooling, TLS 1.2+ configuration, redirect bounding, and transparent Felix User-Agent.

---

## Engine 2 — Secret Intelligence (`felix-secrets`)

Engine 2 analyzes client-side JavaScript bundles and discovered source-map assets from Engine 1 to identify exposed credentials, private keys, provider-specific tokens, and suspicious high-entropy strings.

```text
Engine 1 Assets
      │
      ├── JavaScript
      └── Source Maps
              │
              ▼
           Engine 2
        felix-secrets
              │
     ┌────────┼────────┐
     ▼        ▼        ▼
  Patterns Entropy  Context
     │        │        │
     └────────┼────────┘
              ▼
      Candidate Finding
              │
              ▼
    False Positive Filter
              │
              ▼
        Secret Finding
```

### Supported Secret Families

- **AWS**: AWS Access Key IDs (`AKIA[0-9A-Z]{16}`).
- **Stripe**: Live secret keys (`sk_live_...`, `rk_live_...`). Public keys (`pk_live_`) and test keys (`sk_test_`) are separated.
- **GitHub**: Classic Personal Access Tokens (`ghp_...`) and fine-grained PATs (`github_pat_...`).
- **Slack**: Bot tokens (`xoxb-...`).
- **OpenAI**: Project API keys (`sk-proj-...`) and legacy keys (`sk-...`).
- **Private Cryptographic Keys**: PEM blocks (`-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----`).
- **JWT & Supabase**: Decodes unverified JWT headers and payloads:
  - Distinguishes client-side publishable Supabase `anon` keys (intentionally public; suppressed from secret reports) from privileged `service_role` credentials (flagged as `CRITICAL`).
  - Flags tokens with administrative roles.

### Shannon Entropy & Redaction

- Implements Shannon entropy ($H(X) = -\sum p(x) \log_2 p(x)$) as a candidate heuristic requiring surrounding secret keywords before generating a finding.
- Modular filtering suppresses dummy placeholders (`YOUR_API_KEY`, `REPLACE_ME`, `example-key`), UUIDs, CSS values, and webpack hashes.
- Credential redaction masks sensitive bodies (e.g. `sk_live_********************7890`, `AKIA************MPLE`).
- Inspects source-map `sourcesContent` payloads to discover secrets in original unminified source code.

---

## Engine 3 — Cloud & BaaS Intelligence (`felix-cloud`)

Engine 3 analyzes cloud and Backend-as-a-Service infrastructure discovered by Engine 1 and Engine 2, safely determining whether publicly observable configuration creates an unauthorized exposure.

```text
Engine 1 + Engine 2
        │
        ▼
Discovered URLs / configuration
        │
        ▼
Cloud Provider Detection
        │
 ┌──────┼────────┐
 ▼      ▼        ▼
Supabase Firebase Storage (S3 / GCS)
 │      │        │
 └──────┼────────┘
        ▼
Safe Verification
        │
        ▼
Evidence
        │
        ▼
Cloud Finding
```

### Important Security Principle: Public URL ≠ Vulnerability

> **Felix does NOT consider a public cloud URL or client-visible publishable key a vulnerability by itself.**

A client-visible Supabase `anon` key or public S3 asset bucket URL is standard modern web architecture. Felix distinguishes expected public resources from unauthorized exposures by verifying authorization behavior.

### Provider Capabilities

- **Supabase**:
  - Distinguishes `anon` keys (`INFO: Client Configuration`) from `service_role` keys (`CRITICAL: Privileged Credential Exposure`).
  - **Zero Credential Abuse**: Never transmits requests using discovered `service_role` keys.
  - Safe Authorization Probing: Verifies candidate REST endpoints (e.g. `/rest/v1/products`) actually referenced in application code using `?limit=1`.
  - Proper RLS protection (HTTP 401/403) produces no unauthorized-access finding.
  - If open data is returned (HTTP 200), captures only observed schema field names (`id`, `created_at`, `title`) with record values redacted.
  - Never enumerates arbitrary dictionary table names or dumps databases.
- **Firebase Realtime Database**:
  - Probes discovered `*.firebaseio.com` and `*.firebasedatabase.app` endpoints with shallow non-destructive queries (`/.json?shallow=true&limitToFirst=1`).
  - Protected rules (HTTP 401/403) are verified as secure.
  - Unauthenticated access (HTTP 200) reports top-level key names only, redacting all database contents.
- **Cloud Storage (AWS S3 & Google Cloud Storage)**:
  - Checks if buckets allow anonymous object listing via `?max-keys=1`.
  - 403 Forbidden indicates listing is disabled.
  - If listing is permitted, reports `Anonymous Bucket Listing` without downloading bucket files.
- **Bounded Probing & Rate Limiting**:
  - Dedicated client enforces a 1 MB response limit via `io.LimitReader`.
  - HTTP 429 immediately halts probing for that resource without retry loops.

---

## Engine 4 — Modern API & Endpoint Auditor (`felix-api`)

Engine 4 focuses on modern web API exposure and endpoint security posture, identifying exposed attack surfaces and verifying security conditions without exploiting or modifying the target.

```text
Engine 1 Assets
        │
        ▼
API Endpoint Discovery
        │
 ┌──────┼────────┬────────┐
 ▼      ▼        ▼        ▼
GraphQL CORS  Sensitive Headers
 │      │        │        │
 └──────┼────────┴────────┘
        ▼
Evidence Redaction & Filtering
        │
        ▼
API Finding Inventory
```

### Core Principle

> **Felix identifies exposed attack surfaces and verifies meaningful security conditions without exploiting or modifying the target.**

### Key Capabilities

- **Endpoint Discovery**:
  - Extracts relative API routes (`/api/...`, `/graphql`, `/v1/...`) referenced inside client-side JavaScript assets.
  - Normalizes and bounds discovery to target scope (maximum 25 candidate routes).
  - Reuses Engine 1 data without launching secondary web crawlers.
- **GraphQL Auditing (`pkg/api/graphql.go`)**:
  - Identifies endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`) and executes a non-destructive query for schema metadata (`{ __schema { types { name } } }`).
  - If introspection is enabled, reports type count while omitting schema dumps.
  - Protected endpoints (HTTP 401/403) or 404s generate no exposure findings.
  - Never executes mutations, depth attacks, or denial-of-service queries.
- **CORS Auditing (`pkg/api/cors.go`)**:
  - Sends controlled non-existent probe origin (`https://felix.invalid`) via GET and OPTIONS.
  - Arbitrary origin reflection with credentials (`ACAC: true`) is flagged as `HIGH` severity.
  - Arbitrary origin reflection without credentials is categorized as `LOW` severity.
  - Wildcard policies (`*`) are noted as `INFO`.
  - Does not attempt to read or exfiltrate private user sessions.
- **Sensitive Endpoint Auditing (`pkg/api/endpoints.go`)**:
  - Probes curated sensitive files: `/.env`, `/.env.local`, `/.env.example`, `/.git/HEAD`, `/swagger.json`, `/openapi.json`, `/actuator/health`, `/metrics`.
  - Verifies authentic file structure (e.g. valid key-value assignments for `.env`, valid Git refs for `.git/HEAD`, PromQL metrics syntax).
  - Redacts all sensitive variables, tokens, and metric values.
- **Defensive Security Headers (`pkg/api/headers.go`)**:
  - Inspects `Content-Security-Policy`, `Strict-Transport-Security` (only on HTTPS), `X-Frame-Options`, `X-Content-Type-Options`, and `Permissions-Policy`.
  - Classifies missing headers as hardening findings (`LOW` / `INFO`).
- **Safety & Scope Protection (`pkg/api/client.go`)**:
  - Enforces a 1 MB response limit via `io.LimitReader`.
  - Prohibits cross-origin redirect following to enforce target boundaries.
  - HTTP 429 halts probing immediately without retry loops.

---

## Engine 5 — Finding Correlation, Risk Scoring & Professional Reporting (`felix-report`)

Engine 5 is the final correlation, prioritization, and intelligence layer. It synthesizes signals from Engines 1–4 into explainable security conclusions and generates professional, client-ready reports.

```text
Engine 1 (Crawler) ──┐
Engine 2 (Secrets)  ──┼──► Normalize ──► Deduplicate ──► Correlate ──► Felix Risk Score ──► Prioritize ──► Terminal / JSON / HTML
Engine 3 (Cloud)    ──┤
Engine 4 (API)      ──┘
```

### Core Principle

> **Raw findings are signals. Correlation turns signals into security conclusions.**

### Key Capabilities

- **Unified Finding Model (`pkg/report/model.go`)**:
  - Ingests observations across all engines (`crawler`, `secrets`, `cloud`, `api`) into a structured schema without discarding source metadata.
- **Strict Normalization (`pkg/report/normalize.go`)**:
  - Canonicalizes URLs, removes default ports (:80, :443), standardizes HTTP methods (uppercase), categories (kebab-case), and severity levels while strictly preserving URL path semantics (`/api` vs `/api/`).
- **Identity Deduplication (`pkg/report/dedup.go`)**:
  - Uses SHA-256 identity fingerprints based on target, category, endpoint, method, and key material. Merges multi-asset exposures (e.g. same token across multiple JS bundles) into a single finding with aggregated evidence.
- **Cross-Engine Correlation & Security Stories (`pkg/report/correlate.go`)**:
  - **Case A (Supabase)**: Correlates client-exposed `service_role` credentials with discovered Supabase project endpoints into a Critical threat narrative. Never transmits or tests the credential.
  - **Case B (Firebase)**: Combines open Firebase database discovery with unauthenticated read confirmation.
  - **Case C (GraphQL)**: Unifies GraphQL endpoint detection and public introspection into a single schema-exposure finding.
  - **Case D (API Documentation)**: Correlates OpenAPI/Swagger schema files with discovered client routes without artificial severity escalation.
  - **Case E (.env Exposure)**: Correlates exposed configuration files with active credentials found within application scope.
  - **Case F (CORS Reflection)**: Connects credentialed arbitrary-origin CORS reflection to discovered sensitive backend API routes.
- **Felix Risk Score (`pkg/report/risk.go`)**:
  - Bounded 0–100 integer score based on severity, confidence, privilege levels, and correlation bonuses.
  - Transparent diminishing returns formula preventing low-severity noise from artificially reaching Critical.
  - Categorical bands: **Critical** (80–100), **High** (60–79), **Medium** (40–59), **Low** (20–39), and **Informational** (0–19).
  - *Note*: Felix Risk Score is a defensible prioritization score and is **not** CVSS.
- **Deterministic Prioritization (`pkg/report/summary.go`)**:
  - Sorts findings stably by Severity, Confidence, Risk Score, Category, and Endpoint.
- **Defensive Remediation Engine**:
  - Provides practical, actionable remediation guidance tailored to each finding category.
- **Client-Ready Reporting (`pkg/report/json.go`, `pkg/report/html.go`)**:
  - **JSON Export**: Machine-readable format containing scan metadata, findings, security stories, and risk scores with full evidence sanitization.
  - **HTML Export**: Standalone, offline-ready report with dark cybersecurity theme, executive metrics, and detailed finding breakdowns with zero external CDN dependencies.

---

## Installation & Building

Compile the binary:

```powershell
go build -o bin/felix.exe ./cmd/felix
```

Run test suite:

```powershell
go test -v ./...
go vet ./...
```

---

## Usage

Scan a single target:

```powershell
.\bin\felix.exe scan https://example.com
```

Export results to JSON or HTML:

```powershell
.\bin\felix.exe scan https://example.com --export=report.json
.\bin\felix.exe scan https://example.com --export=report.html
.\bin\felix.exe scan https://example.com --export=report.json,report.html
```

Or pass targets directly:

```powershell
.\bin\felix.exe https://example.com
```

### Options

```text
  -c int
        Number of concurrent workers (default 10)
  -t int
        HTTP timeout in seconds per target (default 10)
  -max-size int
        Maximum asset size limit in MB (default 10)
  -scope string
        Crawl scope mode: same-origin, subdomains, explicit (default "same-origin")
  -user-agent string
        User-Agent header string (default "Felix/0.1")
  -l string
        Path to file containing target URLs (one per line)
  -export string
        Export report to file (e.g. report.json or report.html)
  -v    Enable verbose output
```

### Example Output

```text
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================

[*] Loaded 1 target(s) | Concurrency: 10 | Timeout: 10s | Scope: same-origin

Target: https://example.com

ENGINE 1 — ASSET INGESTION
[+] Assets discovered: 8
[+] JavaScript: 6
[+] Source maps: 2

ENGINE 2 — SECRET INTELLIGENCE
[+] Files analyzed: 8
[+] Confirmed findings: 1

Findings
────────────────────────────────────
CRITICAL Supabase service_role Secret Key
         app.js:481
         Value: eyJhbGciOiJIUzI1NiIsIn...********************.[REDACTED_SIG]
         Confidence: High

ENGINE 3 — CLOUD & BaaS INTELLIGENCE
────────────────────────────────────────
Providers discovered:
  Supabase: 1
  Firebase: 0
  AWS:      0
  GCP:      0

Findings:
  HIGH   Public read access allowed on Supabase resource /rest/v1/products
         Endpoint: https://xyz.supabase.co/rest/v1/products
         Confidence: High

ENGINE 4 — MODERN API & ENDPOINT INTELLIGENCE
────────────────────────────────────────
Endpoints audited: 14
[+] GraphQL endpoints:     1
[+] Sensitive endpoints:   1
[+] CORS observations:     1
[+] Security header checks: 5

Findings:
  HIGH    [cors-origin-reflection] CORS configuration reflects arbitrary Origin with credentials allowed
          Endpoint: https://example.com/api (GET)
          Evidence: Supplied Origin: https://felix.invalid. Response returned Access-Control-Allow-Origin: https://felix.invalid, Access-Control-Allow-Credentials: true
          Confidence: High

  CRITICAL [env-exposure] Public exposure of sensitive /.env configuration file
          Endpoint: https://example.com/.env (GET)
          Evidence: HTTP 200 OK. Observed variable declarations: [APP_ENV, DB_HOST, ...] (secret values redacted).
          Confidence: High

===========================================================
 FELIX :: WEB SECURITY AUDITING REPORT
===========================================================
Target:
https://example.com

Scan completed.

Risk Score: 85/100
Risk Level: CRITICAL

Findings:
  CRITICAL  2
  HIGH      2
  MEDIUM    0
  LOW       3
  INFO      2

CORRELATED SECURITY STORIES (2)
────────────────────────────────────────
[CRITICAL] Privileged Supabase Cloud Credential Exposure
  Impact:      A privileged service_role credential completely bypasses Row Level Security (RLS), granting administrative database access if exposed to untrusted users.
  Remediation: Immediately revoke and rotate the exposed service_role key in the provider dashboard. Ensure administrative operations run exclusively on server-side functions and never bundle privileged keys in client-accessible assets.

[CRITICAL] Exposed Environment Configuration with Active Credentials
  Impact:      Direct exposure of production environment variables containing active secret keys permits direct compromise of connected backend databases, cloud storage, and APIs.
  Remediation: Immediately remove .env and environment configuration files from web server document roots. Rotate all credentials declared in the file.

TOP PRIORITIES
────────────────────────────────────────
[CRITICAL] Supabase service_role Secret Key
Confidence: HIGH
Endpoint:   https://example.com/app.js (GET)
Action:     Immediately revoke and rotate the exposed service_role key in the provider dashboard. Ensure administrative operations run exclusively on server-side functions.

[CRITICAL] Public exposure of sensitive /.env configuration file
Confidence: HIGH
Endpoint:   https://example.com/.env (GET)
Action:     Immediately remove .env and environment configuration files from web server document roots. Rotate all credentials declared in the file.

Reports:
  HTML: report.html
  JSON: report.json

[*] Scan complete. 8 asset(s) ingested, 9 finding(s) reported (Risk: 85/100, CRITICAL) across 1 target(s).
```

---

## Safety & Defensive Boundaries

Felix is strictly designed for authorized defensive security assessments:
- **No Exploitation or Data Exfiltration**: Never dumps databases, downloads storage objects, or executes state-modifying requests (no POST/PUT/DELETE payload exploitation).
- **No Brute-Forcing or Wordlists**: Probes only bounded, application-referenced routes and standard security metadata paths.
- **No Credential Guessing**: Never attempts to guess passwords, test stolen API keys, or brute-force authentication.
- **Strict Evidence Redaction**: Passwords, API tokens, JWTs, and database records are always masked in memory and terminal outputs.
- **Deterministic Prioritization**: Risk scores reflect defensible evidence without artificial inflation or speculative claims.
