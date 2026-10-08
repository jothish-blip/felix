# Felix

> **Deterministic Web Security Auditing Platform**  
> *"Attackers rely on luck. Felix leaves them zero."*

[![Go Test](https://img.shields.io/badge/go%20test-162%2F162%20passing-brightgreen)](#)
[![Go Vet](https://img.shields.io/badge/go%20vet-clean-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)](#)

Felix is an evidence-first, non-destructive web security auditing platform written in Go. Designed for application security engineers, penetration testers, and DevSecOps pipelines, Felix audits web assets, client JavaScript bundles, modern APIs, and cloud backends without invasive exploits, fuzzing, or destructive payloads.

---

## Documentation Map

- **[Architecture Guide](ARCHITECTURE.md)** — Deep dive into system components, data flow, concurrency, and pipeline design.
- **[Operator Usage Guide](USAGE.md)** — CLI command reference, flag syntax, examples, shell completions, and configuration.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — The 5-stage evidence model, pattern registries, heuristic filters, and verification states.
- **[Security & Safety Controls](SECURITY.md)** — Non-destructive design principles, scope boundaries, token handling, and safety guarantees.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Honest appraisal of black-box testing boundaries, SPA execution, and false positive trade-offs.
- **[Contributing Guide](CONTRIBUTING.md)** — Codebase conventions, test frameworks, regression suites, and pull request guidelines.

---

## Core Security Model

The foundational philosophy of Felix is simple:

> **Discovery ≠ Detection ≠ Verification ≠ Vulnerability**

A security observation must never be misclassified as a confirmed vulnerability without verifiable, empirical evidence:

```text
Discovery
    ↓   Found an asset, route, endpoint, or pattern
Detection
    ↓   Identified a security-relevant candidate or condition
Verification
    ↓   Established empirical proof (or negative evidence)
Evidence
    ↓   Recorded HTTP status, headers, location, and negative observations
Risk
    ↓   Deterministic 0–100 scoring based on verified exposure
Security Story
    ↓   Correlated multi-signal narrative prioritizing remediation
Report
        Self-contained strict-black HTML, sanitized JSON, or terminal summary
```

---

## Key Capabilities

- **Asset & Endpoint Discovery:** Safe concurrent ingestion of HTML, JavaScript bundles, stylesheets, manifests, and production source maps with strict scope boundaries.
- **Secret Intelligence:** Shannon entropy heuristics combined with contextual keyword weighting, structured alphabet filtering, and aggressive false-positive reduction for over 20+ secret patterns.
- **Cloud & BaaS Auditing:** Non-destructive exposure verification for Supabase, Firebase Realtime Database, AWS S3, and Google Cloud Storage. Distinguishes public config from unauthorized data exposure.
- **Modern API Analysis:** Static route extraction, endpoint taxonomy classification, authentication-state reasoning (200, 401, 403, 404, 308), sensitive path probing, GraphQL introspection checks, and credentialed CORS reflection analysis.
- **Defensive Headers Evaluation:** Verification of Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Permissions-Policy, and Referrer-Policy.
- **Correlated Security Stories:** Multi-signal relationship correlation grouping isolated observations into unified incident stories with concrete remediation steps.
- **Deterministic 0–100 Risk Score:** An explainable risk prioritization metric weighted by verification certainty, negative evidence reductions, and defense-in-depth caps. (Not CVSS).
- **Decoupled Offline Reporting:** A single scan generates a reusable scan result. Subsequent HTML and JSON report generations perform **zero network requests**.
- **Pure Black Mode HTML Reports:** Self-contained, responsive assessment reports with `#000000` pure black foundations, zero external CDN dependencies, interactive filters, and client-side instant search.

---

## What Felix Does vs. What Felix Does Not Do

| What Felix Does | What Felix Does Not Do |
| :--- | :--- |
| Ingests in-scope client assets and JavaScript bundles | Execute client-side JavaScript runtimes (no browser DOM rendering) |
| Extracts API routes and GraphQL endpoints from client code | Perform aggressive brute-force path enumeration or fuzzing |
| Validates response headers, clickjacking defense, and CORS policies | Exploit vulnerabilities, inject SQLi, or execute XSS payloads |
| Verifies public cloud configurations using safe, read-only GET/HEAD checks | Transmit discovered client credentials to external administrative APIs |
| Records negative evidence (e.g. 401/403/404) to prevent false positives | Attempt to bypass authentication gates or escalate privileges |
| Produces deterministic, explainable risk scores and correlated stories | Guarantee the total absence of vulnerabilities across an application |

---

## Quick Start

### Installation

#### Windows (PowerShell)
```powershell
# Run the automated installer
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1

# Or install from compiled binary
felix install
```

#### Linux & macOS (POSIX)
```bash
# Run the automated installer
./scripts/install.sh

# Or install from compiled binary
felix install
```

#### From Source (Go 1.22+)
```bash
git clone https://github.com/jothish-blip/felix.git
cd felix
go build -o bin/felix ./cmd/felix
```

### System Health Diagnostic
Validate your runtime environment, TLS stack, report subsystem, and PATH:
```bash
felix doctor
```

---

## Basic Scanning

### 1. Basic Web Audit
Execute a non-destructive audit against an authorized target:
```bash
felix scan https://example.com
```

### 2. Export HTML Assessment Report
Generate a single-file, self-contained HTML assessment report:
```bash
felix scan https://example.com --export report.html
```

### 3. Generate Reusable JSON Scan Result
Save the machine-readable scan result without rescanning:
```bash
felix scan https://example.com --json scan-result.json
```

### 4. Zero-Network Offline Reporting
Generate an HTML report from a previously saved JSON scan result with **zero network activity**:
```bash
felix report scan-result.json --html offline-report.html
```

---

## Example Terminal Output

```text
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================
[*] Loaded 1 target(s) | Concurrency: 10 | Timeout: 10s | Scope: same-origin

Target: https://example.com

ASSET DISCOVERY
────────────────────────────────────────
[+] Assets discovered: 1
[+] JavaScript: 1

SECRET INTELLIGENCE
────────────────────────────────────────
[+] Files analyzed: 1
[+] Findings detected: 0

CLOUD & BaaS INTELLIGENCE
────────────────────────────────────────
Providers discovered:
  Supabase: 0
  Firebase: 0
  AWS:      0
  GCP:      0

API SECURITY AUDITING
────────────────────────────────────────
Endpoints audited: 11
[+] GraphQL endpoints:     0
[+] Sensitive endpoints:   0
[+] CORS observations:     0
[+] Security header checks: 6

===========================================================
 FELIX :: SECURITY ASSESSMENT REPORT
===========================================================
Target:     https://example.com
Timestamp:  2026-10-08T17:07:22Z
Duration:   1.297s
Risk Score: 20/100 (LOW)

Findings Summary:
  CRITICAL  0
  HIGH      0
  MEDIUM    0
  LOW       3
  INFO      3

Verification Status:
  VERIFIED     6
  DETECTED     0
  OBSERVED     0

Top Priorities:
────────────────────────────────────────
[LOW] Missing Content-Security-Policy (CSP) defense-in-depth header
  Confidence:   HIGH
  Verification: VERIFIED
  Location:     https://example.com
  Negative Note:Informational hardening observation; does not constitute an exploitable vulnerability by itself.
  Remediation:  Deploy a robust Content-Security-Policy (CSP) header restricting script execution to trusted sources.

[*] Assessment complete in 1.297s. 1 asset(s) ingested, 6 finding(s) discovered across 1 target(s).
```

---

## CLI Overview

| Subcommand | Purpose |
| :--- | :--- |
| `felix scan <target> [flags]` | Conduct an automated security audit against a target web application. |
| `felix report <result.json> [flags]` | Generate HTML or JSON reports from saved results (**zero network requests**). |
| `felix config [subcommand]` | View and manage persistent defaults in `~/.felix/config.json`. |
| `felix doctor` | Validate binary integrity, Go runtime, network stack, and permissions. |
| `felix version` | Display Felix version, platform architecture, and compiler details. |
| `felix completion [shell]` | Generate native shell autocompletion (PowerShell, Bash, Zsh, Fish). |
| `felix install` | Register the Felix executable in the user system PATH. |
| `felix uninstall` | Remove the Felix executable from the user system PATH. |
| `felix help [command]` | Display usage instructions and flag options. |

### Scan Controls
- `--timeout <duration>`: Request timeout per target (e.g. `10s`, `30s`, `1m`).
- `--concurrency <int>`: Number of concurrent workers (positive integer).
- `--scope <mode>`: Scope boundary (`same-origin`, `subdomains`, `explicit`).
- `--max-assets <int>`: Enforce an upper bound on assets processed.
- `--max-response-size <size>`: Maximum response byte limit (e.g. `5MB`, `10MB`, `512KB`).
- `--export <file>`: Output assessment report (`report.html` or `report.json`).
- `--json [file]`: Save or output machine-readable scan result.
- `--quiet, -q`: Suppress human-readable progress and banners.
- `--verbose, -v`: Display operational scan parameters and assets inventory safely.

---

## Exit Code Contract

Felix enforces deterministic Unix exit codes suitable for automation and CI/CD pipelines:

- **`0` (Clean / Informational):** Scan completed successfully with zero actionable findings (or informational observations only).
- **`1` (Actionable Findings):** Scan identified security conditions requiring review (Low, Medium, High, or Critical severity).
- **`2` (Usage / Runtime Error):** CLI syntax error, invalid arguments, conflicting flags, or unreachable target.

---

## License

Felix is licensed under the [MIT License](LICENSE).
