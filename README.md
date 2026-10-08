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
│   └── secrets/               # Engine 2: Secret Intelligence
│       ├── detector.go        # Scanner orchestration & context evaluation
│       ├── patterns.go        # Signature registry & JWT inspector
│       ├── entropy.go         # Shannon entropy calculation
│       ├── finding.go         # Secret finding model & redaction
│       ├── filters.go         # False positive & placeholder filtering
│       └── detector_test.go   # Engine 2 test suite
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

### Shannon Entropy Analysis

Implements character-level Shannon entropy:
$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
Entropy is treated as a candidate signal, not an automatic critical finding. High-entropy strings ($H \ge 4.5$) undergo context evaluation, looking for nearby variable names such as `key`, `secret`, `token`, or `auth`.

### False-Positive Filtering

Modular filtering suppresses non-actionable noise:
- Known documentation and tutorial placeholders (`YOUR_API_KEY`, `REPLACE_ME`, `example-key`, `dummy`).
- Webpack chunk hashes and build artifacts.
- UUIDs, CSS color values, and base64 data URIs.
- Unstructured hex strings without sensitive context.

### Secret Redaction

Felix strictly enforces credential redaction:
- Full raw secrets are never printed to the terminal, stdout, or reports.
- High-risk credentials are masked (e.g. `sk_live_********************7890`, `AKIA************MPLE`).
- Private keys have payload bodies completely replaced with `[REDACTED PRIVATE KEY]`.

### Source Map Analysis

When Engine 1 captures source maps (`.map`), Engine 2 inspects embedded `sourcesContent` payloads to discover secrets in original unminified source code, reporting the original source path and line number.

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
[+] Confirmed findings: 2

Findings
────────────────────────────────────
HIGH    Stripe Live Secret Key
        app.js:481
        Value: sk_live_********************7890
        Confidence: High

CRITICAL Private Cryptographic Key
        webpack:///src/config/server.ts:12
        Value: -----BEGIN RSA PRIVATE KEY-----... [REDACTED PRIVATE KEY] ...
        Confidence: High

[*] Scan complete. 8 total asset(s) ingested, 2 secret finding(s) discovered across 1 target(s).
```

---

## Safety & Limitations

- **Passive Analysis**: Engine 2 is purely passive. It performs static analysis on downloaded assets without making outbound requests to validate credentials.
- **No Live Validation**: Felix does not attempt to authenticate against third-party APIs (AWS, Stripe, OpenAI, etc.), spend credits, or determine whether discovered keys are currently active in production.
- **Defensive Auditing Only**: No brute forcing, credential stuffing, or destructive payloads.
