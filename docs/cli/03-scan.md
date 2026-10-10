# FELIX CLI :: Audit & Scan Engine (`felix scan`)

> **Module 03** | Complete guide to `felix scan`, flag controls, reachability error handling, assessment states, and test scenarios.

---

## 1. Overview & Syntax

The `scan` command performs non-destructive security audits against web applications, client JavaScript bundles, modern APIs, and cloud backends:

```bash
felix scan [options] <target-url>
```

Alternatively, a batch of targets can be passed via a file:
```bash
felix scan -l targets.txt [options]
```

---

## 2. Comprehensive Flag Reference

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--timeout <duration>` | `-t` | `10s` | Network timeout per target request (e.g. `5s`, `30s`, `1m`). |
| `--concurrency <int>` | `-c` | `10` | Maximum concurrent worker goroutines for crawling and analysis. |
| `--scope <mode>` | — | `same-origin` | Crawl boundary mode: `same-origin`, `subdomains`, or `explicit`. |
| `--max-assets <int>` | — | Unlimited | Maximum number of frontend assets/scripts to crawl and ingest. |
| `--max-response-size <size>`| `--max-size` | `10MB` | Response body limit to prevent memory exhaustion (e.g. `5MB`, `512KB`). |
| `--export <file>` | — | — | Export assessment report to HTML, JSON, or SARIF based on file extension. |
| `--json [file]` | — | `scan-result.json` | Save machine-readable JSON scan result (outputs to stdout if no file given). |
| `--sarif [file]` | — | `scan-result.sarif`| Export standard OASIS SARIF 2.1.0 report for CI/CD security scanning. |
| `--quiet` | `-q`, `-s` | `false` | Suppress progress output and ASCII banners. |
| `--verbose` | `-v` | `false` | Display granular operational discovery logs and asset inventories. |
| `-l <file>` | — | — | Path to a line-separated text file of target URLs. |
| `--user-agent <string>` | — | Built-in | Custom HTTP `User-Agent` header for requests. |

---

## 3. Assessment States & Lifecycle

FELIX classifies every assessment into one of four deterministic states:

```text
              Initial Reachability Check
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
   Reachable                         Unreachable
        │                                 │
   Run Crawl & Analysis             ┌─────┴──────────────┐
        │                           ▼                    ▼
   ┌────┴────────────┐          DNS / Refusal       Host Timeout
   ▼                 ▼              │                    │
Zero Errors     Partial Errors      ▼                    ▼
   │                 │           BLOCKED               FAILED
   ▼                 ▼
COMPLETED         PARTIAL
```

### State Definitions:
1. **`COMPLETED`**:
   - The root target and discovered assets were successfully fetched and analyzed without fatal interruption.
   - Overall Risk Score (0–100) is **fully calculated**, attributed, and displayed.
2. **`PARTIAL`**:
   - The primary target was reachable, but some secondary assets encountered non-fatal network errors (e.g. 404, TLS warning, timeout on a single bundle).
   - Findings from reachable assets are reported.
   - Risk score reflects verified findings from completed analysis.
3. **`BLOCKED`**:
   - Target is unreachable due to deterministic environmental blocks: DNS resolution failure (`NXDOMAIN`), TCP connection refused (`ECONNREFUSED`), or client certificate rejection.
   - Assessment halts immediately.
   - Overall Risk Score is reported as **`N/A`** (`--`) to prevent misleading security ratings for uninspected targets.
   - Exit code: `2`.
4. **`FAILED`**:
   - Target is unreachable due to severe transport failures, total network timeout, or connection reset during initial handshake.
   - Assessment halts immediately.
   - Overall Risk Score is reported as **`N/A`** (`--`).
   - Exit code: `2`.

---

## 4. HTTP Reachability Classification

Before launching deep crawlers, FELIX executes a classified reachability probe via `pkg/crawler/reachability.go`:

| Classification | Underlying Error | Outcome & Assessment State |
| :--- | :--- | :--- |
| **`DNS_ERROR`** | `net.DNSError` (Host not found) | Assessment `BLOCKED` (Exit 2) |
| **`CONNECTION_REFUSED`** | `syscall.WSAECONNREFUSED` / `ECONNREFUSED` | Assessment `BLOCKED` (Exit 2) |
| **`TLS_ERROR`** | Certificate invalid, authority unknown | Assessment `BLOCKED` (Exit 2) |
| **`TIMEOUT`** | `os.ErrDeadlineExceeded`, i/o timeout | Assessment `FAILED` (Exit 2) |
| **`HTTP_ERROR`** | HTTP 5xx Server Error / 403 Forbidden | Assessment `PARTIAL` or proceeding with negative evidence |
| **`SUCCESS`** | HTTP 200 OK / 301/302 Redirect | Assessment proceeds to `COMPLETED` |

---

## 5. Scope Enforcement Modes

1. **`same-origin`** (Default):
   - Only crawl URLs matching the exact scheme, host, and port of the initial target.
   - Example target: `https://app.example.com`
   - In-scope: `https://app.example.com/api/v1`
   - Out-of-scope: `https://api.example.com`, `http://app.example.com`, `https://example.com`
2. **`subdomains`**:
   - Crawl any subdomain belonging to the target's base domain.
   - Example target: `https://app.example.com`
   - In-scope: `https://api.example.com`, `https://cdn.example.com`
   - Out-of-scope: `https://external-service.com`
3. **`explicit`**:
   - Strict crawling limited only to explicitly supplied URLs (no recursive link following).

---

## 6. Output Formats

### 1. HTML Assessment Report (`--export report.html`)
- Completely standalone, pure-black theme (`#000000`).
- Zero external CDN dependencies (fonts, styles, icons, scripts embedded inline).
- Full interactive client-side instant search, severity filters, evidence inspection drawer, and copy-to-clipboard curl commands.

### 2. JSON Scan Result (`--json scan.json`)
- Complete machine-readable audit dossier.
- Contains metadata, target URL, duration, assessment state, findings, verified evidence, attack paths, and risk score breakdown.

### 3. OASIS SARIF 2.1.0 (`--sarif scan.sarif`)
- Fully compliant with OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0.
- Directly importable into GitHub Code Scanning alerts, GitLab SAST, SonarQube, and DefectDojo.

---

## 7. Practical Learning Exercises

### Exercise 3.1: Audit a Local Service (e.g. Juice Shop)
If you have OWASP Juice Shop running locally on `http://127.0.0.1:3000`:
```powershell
.\bin\felix.exe scan http://127.0.0.1:3000 --export test-juice.html --json test-juice.json
```
Verify generated files:
```powershell
Test-Path test-juice.html
Test-Path test-juice.json
```

### Exercise 3.2: Verify Reachability Error Handling (Non-existent Domain)
```powershell
.\bin\felix.exe scan https://non-existent-domain-felix-test.invalid --timeout 3s
$LASTEXITCODE
```
*(Expected: Assessment terminates as `BLOCKED`, error message indicates DNS failure, exit code is `2`).*

### Exercise 3.3: Verify Connection Refusal Handling (Unopened Port)
```powershell
.\bin\felix.exe scan http://127.0.0.1:59999 --timeout 2s
$LASTEXITCODE
```
*(Expected: Assessment terminates as `BLOCKED`, connection refused clearly identified, exit code is `2`).*

### Exercise 3.4: Test SARIF Export
```powershell
.\bin\felix.exe scan http://127.0.0.1:3000 --sarif test-juice.sarif --quiet
Get-Content test-juice.sarif -TotalCount 10
```
*(Expected: Generates valid SARIF schema file with `"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"`).*
