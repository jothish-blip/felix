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
│   └── cloud/                 # Engine 3: Cloud & BaaS Intelligence
│       ├── provider.go        # Provider enums & service models
│       ├── detector.go        # Provider discovery & verification coordinator
│       ├── finding.go         # Cloud finding model & deduplication
│       ├── supabase.go        # Supabase RLS auditor & key separation
│       ├── firebase.go        # Firebase Realtime Database auditor
│       ├── storage.go         # AWS S3 & GCP Cloud Storage auditor
│       ├── client.go          # Bounded HTTP probe client
│       └── cloud_test.go      # Engine 3 test suite
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
HIGH    Stripe Live Secret Key
        app.js:481
        Value: sk_live_********************7890
        Confidence: High

ENGINE 3 — CLOUD & BaaS INTELLIGENCE
────────────────────────────────────────
Providers discovered:
  Supabase: 1
  Firebase: 0
  AWS:      1
  GCP:      0

Findings:
  HIGH   Public read access allowed on Supabase resource /rest/v1/products
         Endpoint: https://xyz.supabase.co/rest/v1/products
         Confidence: High

  INFO   Supabase publishable anon key detected
         Endpoint: https://xyz.supabase.co
         Confidence: High

[*] Scan complete. 8 total asset(s) ingested, 1 secret finding(s), 2 cloud finding(s) discovered across 1 target(s).
```

---

## Safety & Limitations

- **Passive & Non-Destructive**: Felix performs static analysis and bounded, non-destructive read requests only.
- **No Exploitation or Data Exfiltration**: Never dumps databases, downloads storage objects, or executes state-modifying requests (no POST, PUT, DELETE).
- **No Live Credential Testing**: Never tests discovered secret tokens or `service_role` keys against third-party provider APIs.
- **Defensive Auditing Only**: Designed strictly for authorized security assessments.
