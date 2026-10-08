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
│   └── crawler/
│       ├── asset.go           # Asset model, classification & source map detection
│       ├── config.go          # Engine configuration & defaults
│       ├── crawler.go         # Core crawler pipeline & concurrent worker pool
│       ├── crawler_test.go    # Test suite (unit & mock HTTP integration tests)
│       └── scope.go           # Origin & host scope boundary enforcement
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

---

## Engine 1 — Felix Crawler

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

- **Asset Ingestion Model (`Asset`)**: Fully decoupled data structure storing asset URL, type (`javascript`, `stylesheet`, `manifest`, `source-map`), raw content, status codes, and size. Ready for downstream consumption by Engine 2 (`felix-secrets`).
- **Concurrent Worker Pool**: Bounded goroutines with semaphore-controlled concurrency.
- **Strict Scope Boundaries**: Default same-origin enforcement prevents unauthorized cross-origin requests while recording discovered external references.
- **Memory & Response Safety**: Configurable maximum asset size limit (default 10 MB) via bounded `io.LimitReader` stream reads.
- **Source Map Discovery**: Automatic discovery and relative resolution of `//# sourceMappingURL=...` declarations in JavaScript bundles.
- **Hardened HTTP Client**: Connection pooling, TLS 1.2+ configuration, redirect bounding, and transparent Felix User-Agent.

---

## Installation & Building

Compile the binary:

```powershell
go build -o bin/felix.exe ./cmd/felix
```

Run tests:

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

[+] Target reachable
[+] HTML retrieved
[+] Assets discovered: 5
[+] JavaScript: 3
[+] Stylesheets: 1
[+] Source maps: 1

Assets
────────────────────────────────────────
JS       https://example.com/_next/static/chunks/main.js
JS       https://example.com/assets/vendor.js
CSS      https://example.com/assets/style.css
MAP      https://example.com/_next/static/chunks/main.js.map
JS       https://cdn.example.com/tracker.js [external / skipped]

[*] Scan complete. 5 total asset(s) ingested across 1 target(s).
```

---

## Security Boundaries

Felix is strictly designed for authorized, defensive security assessments:
- Safe asset discovery and collection only
- No brute forcing, credential attacks, or aggressive fuzzing
- No destructive requests or database modification
