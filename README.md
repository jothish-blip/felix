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

- **[CLI Learning Guide (docs/cli/)](docs/cli/README.md)** — Comprehensive command-by-command learning, testing, and flag verification guide.
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

- **Attack-Surface Intelligence (Felix 2.0):** Relational attack surface inventory connecting domains, subdomains, web applications, API bases, endpoints, forms, parameters, authentication surfaces, cloud dependencies, and technologies with strict scope isolation.
- **Authentication Intelligence (Stage 3):** Multi-signal discovery of authentication surfaces (Login, Registration, Password Reset, MFA, Session, OAuth SSO), passive cookie security auditing (Secure, HttpOnly, SameSite; zero secret value persistence), static token structure analysis (JWT algorithm inspection, PKCE method verification), and empirical endpoint protection reasoning (401/403/302/200) without credential probing or session replay.
- **Form & Parameter Analysis:** Static extraction of HTML forms and control elements without executing submissions; detection of query, path, and body parameters with type inference.
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

## Platform Support & Verification Status

Felix is engineered as a pure-Go application (`CGO_ENABLED=0`) with zero external C dependencies, utilizing a pure-Go SQLite engine (`modernc.org/sqlite`). To ensure strict engineering honesty, Felix distinguishes between **compilation verification**, **automated CI testing**, and **native host runtime verification**:

| Platform | Architecture | Compilation | Automated CI Tests | Native Runtime Verification |
| :--- | :--- | :---: | :---: | :---: |
| **Windows** | x86_64 (`amd64`) | **Verified** | **Verified** (22 suites passing) | **Verified** (Local testing & live targets) |
| **Linux** | x86_64 (`amd64`) | **Verified** (ELF binary) | **Verified** (GitHub Actions `ubuntu-latest`) | **Pending Native Host Testing** |
| **Linux** | ARM64 (`aarch64`) | **Verified** (ELF binary) | Cross-compiled | **Pending Native Host Testing** |
| **macOS** | Apple Silicon (`arm64`)| **Verified** (Mach-O binary) | Cross-compiled | **Pending Native Host Testing** |
| **macOS** | Intel (`amd64`) | **Verified** (Mach-O binary) | Cross-compiled | **Pending Native Host Testing** |

> [!NOTE]
> **Portability Architecture**: Because Felix contains zero CGO dependencies and zero platform-specific build tags, cross-compilation produces fully functional standalone native binaries. Native Linux and macOS host validation is scheduled for subsequent controlled testing phases.

---

## Build from Source

You can build Felix from source on any platform with Go 1.22+ installed. Zero external C compilers or development headers are required.

### 1. Prerequisites
- **Go Toolchain:** Go 1.22 or higher (developed and verified on Go 1.27.0).
- **CGO:** Disabled (`CGO_ENABLED=0`).
- **Git:** For cloning the source repository.

### 2. Native Build (Current Host)
```bash
git clone https://github.com/jothish-blip/felix.git
cd felix
go build -trimpath -ldflags="-s -w" -o bin/felix ./cmd/felix
```

### 3. Cross-Compilation Commands
Because Felix is 100% pure Go, you can compile for any supported target directly from your current machine:

```powershell
# Windows PowerShell -> Linux amd64
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"; go build -trimpath -ldflags="-s -w" -o bin/felix-linux-amd64 ./cmd/felix; $env:GOOS="windows"

# Windows PowerShell -> macOS Apple Silicon (arm64)
$env:GOOS="darwin"; $env:GOARCH="arm64"; $env:CGO_ENABLED="0"; go build -trimpath -ldflags="-s -w" -o bin/felix-darwin-arm64 ./cmd/felix; $env:GOOS="windows"
```

```bash
# Linux / macOS (POSIX) -> Windows amd64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/felix.exe ./cmd/felix

# Linux / macOS (POSIX) -> Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/felix-linux-arm64 ./cmd/felix
```

---

## Installation

Felix is distributed through native package managers for Kali Linux/Debian and macOS, as well as standalone signed binaries for Windows and POSIX systems.

For full distribution details, APT repository keys, and troubleshooting, see the **[Production Installation Guide (docs/INSTALLATION.md)](docs/INSTALLATION.md)**.

### Kali Linux, Debian & Ubuntu (APT)

```bash
# 1. One-time repository and GPG signing key configuration
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://jothish-blip.github.io/apt-repo/felix-archive-keyring.gpg | sudo tee /etc/apt/keyrings/felix-archive-keyring.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/felix-archive-keyring.gpg] https://jothish-blip.github.io/apt-repo stable main" | sudo tee /etc/apt/sources.list.d/felix.list > /dev/null

# 2. Update and install Felix
sudo apt update
sudo apt install felix
```

### macOS (Homebrew Tap)

Install via the official verified Homebrew tap:

```bash
brew install jothish-blip/tap/felix
```

*(Alternatively: `brew tap jothish-blip/tap && brew install felix`)*

---

## Download Felix v2.0.0

Download pre-compiled, standalone binaries and packages from the **[Official GitHub Releases](https://github.com/jothish-blip/felix/releases/tag/v2.0.0)** page.

| Platform | Architecture | Standalone Binary | Package Archive / Debian Package | Checksum |
| :--- | :--- | :--- | :--- | :--- |
| **Windows** | x86_64 / amd64 | [`felix_windows_amd64.exe`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_windows_amd64.exe) | [`felix_2.0.0_windows_amd64.zip`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_windows_amd64.zip) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |
| **Linux (Debian/Kali)** | x86_64 / amd64 | [`felix_linux_amd64`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_linux_amd64) | [`felix_2.0.0_amd64.deb`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_amd64.deb) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |
| **Linux (Debian/Kali)** | ARM64 / aarch64 | [`felix_linux_arm64`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_linux_arm64) | [`felix_2.0.0_arm64.deb`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_arm64.deb) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |
| **Linux (Tarball)** | x86_64 / amd64 | [`felix_linux_amd64`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_linux_amd64) | [`felix_2.0.0_linux_amd64.tar.gz`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_linux_amd64.tar.gz) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |
| **macOS** | Intel (x86_64) | [`felix_darwin_amd64`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_darwin_amd64) | [`felix_2.0.0_darwin_amd64.tar.gz`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_darwin_amd64.tar.gz) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |
| **macOS** | Apple Silicon (M-series) | [`felix_darwin_arm64`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_darwin_arm64) | [`felix_2.0.0_darwin_arm64.tar.gz`](https://github.com/jothish-blip/felix/releases/download/v2.0.0/felix_2.0.0_darwin_arm64.tar.gz) | [SHA256SUMS](https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS) |

### Integrity Verification

Verify the SHA-256 hash of your downloaded binary before execution:

```powershell
# Windows PowerShell
Get-FileHash .\felix_2.0.0_windows_amd64.zip -Algorithm SHA256
```

```bash
# Linux / macOS
sha256sum felix_2.0.0_linux_amd64.tar.gz
# or Debian package
sha256sum felix_2.0.0_amd64.deb
```

---

## Windows Installation

Felix provides two distinct Windows installation paths:

### Path A: Developer / Local Testing — FREE (No Azure / No Paid Certificates)
For developers, security analysts, and contributors running Felix on their own Windows machines:

1. **Run Developer Setup:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\setup-dev.ps1
   ```
   This signs `felix.exe` with local development Authenticode, installs Felix to `%LOCALAPPDATA%\Felix\bin`, and registers it in User `PATH`.

To remove development trust at any time:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-dev-trust.ps1
```

### Path B: Public Production Distribution (Official Releases)
1. Download `felix_windows_amd64.exe` or `felix_2.0.0_windows_amd64.zip` from [Official GitHub Releases](https://github.com/jothish-blip/felix/releases/tag/v2.0.0).
2. Run the installer:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install\install.ps1
   ```

### Manual Linux & macOS (POSIX) Tarball Install
```bash
tar -xzf felix_2.0.0_linux_amd64.tar.gz
mkdir -p ~/.felix/bin
mv felix ~/.felix/bin/
export PATH="$HOME/.felix/bin:$PATH"
```
2. Verify installation:
   ```bash
   felix version
   felix doctor
   felix scan https://example.com --export report.html --json result.json
   ```

### Secure Updates
Felix includes a built-in cryptographic updater to check for and install releases directly from official GitHub distribution channels:

```bash
# Check if a new version is available (does not download or modify files)
felix update --check

# Download, verify SHA256 checksum, stage, and safely self-replace with rollback
felix update
```

---

## Trusted Distribution & Integrity

- **Cryptographic Checksums:** Every release package and binary is accompanied by an authoritative `SHA256SUMS` manifest and machine-readable `update.json` metadata.
- **Windows Signing:** Windows binaries are Authenticode/Artifact Signing signed when the production signing integration is configured. *(Note: As with all newly published Windows executables, Microsoft Defender SmartScreen reputation develops over initial download volume).*
- **macOS Gatekeeper:** macOS binaries are Developer ID signed and notarized when Apple signing credentials are configured.
- **Atomic Replacement & Rollback:** `felix update` validates SHA256 hashes, unpacks in a sandbox with ZipSlip mitigation, verifies binary execution in a sub-process, and restores the previous binary automatically if replacement or validation fails.
- **No Background Telemetry:** Felix respects user privacy. Updates are only checked when explicitly commanded via `felix update --check` or `felix update`. Zero telemetry, tracking, or background daemons.

---

## Basic Scanning

### 1. Basic Web Audit
Execute a non-destructive audit against an authorized target:
```bash
felix scan https://example.com
```

### 2. Export HTML Assessment Report
Export an offline HTML report:
```bash
felix scan https://example.com --export report.html
```

### 3. Machine-Readable JSON Export
Export structured JSON results for pipeline integration:
```bash
felix scan https://example.com --json scan-result.json
```
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

## Felix 2.0 — Assessment Platform & Traceability Core

Felix 2.0 introduces a structured, client-aware security assessment engine with complete relational traceability:

```text
Client ──► Authorization ──► Approved Scope ──► Assessment ──► Execution ──► Findings ──► Report
```

### Complete Assessment Lifecycle

```bash
# 1. Register a client organization
felix client add --name "Acme Corporation" --org "Acme Corp Ltd" --contact-email "security@acme.example"

# 2. Create an assessment project
felix assessment create --client "Acme Corporation" --name "Q1 Web Security Audit" --target https://app.acme.example --scope-mode same-origin

# 3. Add secondary targets, scope rules, or exclusions
felix assessment target add ASM-2026-0001 --url https://api.acme.example
felix assessment scope add ASM-2026-0001 --rule "subdomains:acme.example"
felix assessment exclude add ASM-2026-0001 --type PATH_PREFIX --pattern /admin --reason "Out of test boundary"

# 4. Record explicit client authorization (Assessment transitions from DRAFT to READY)
felix assessment authorize ASM-2026-0001 --authorizer "Jane Doe" --role "Head of Security" --reference "SEC-AUTH-2026-01" --valid-days 30

# 5. Execute authorized assessment (Fails closed if unauthorized or expired)
felix assessment run ASM-2026-0001 --concurrency 5 --timeout 15s

# 6. Review recorded findings and generated reports
felix assessment findings ASM-2026-0001
felix assessment reports ASM-2026-0001
```

### Core Assessment Architectural Guarantees
- **Fail-Closed Execution Refusal:** Unrecorded, pending, expired, or revoked authorizations strictly block scan execution.
- **Strict Exclusion Precedence:** Exclusions (`HOSTNAME`, `PATH_PREFIX`, `EXACT_URL`) strictly override any broader scope rule or target allowance.
- **Relational Finding Traceability:** Every finding in `~/.felix/assessments.db` is immutably linked to `AssessmentID`, `ExecutionID`, `TargetID`, with full evidence and verification records intact.
- **Embedded Pure-Go SQLite:** Uses a pure-Go driver (`modernc.org/sqlite`) with WAL mode, foreign keys, and automatic schema migrations—maintaining `CGO_ENABLED=0` cross-compilation across all 5 platforms.


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
| `felix client <subcommand> [flags]` | Manage clients and organizations for structured security auditing. |
| `felix assessment <subcommand> [flags]` | Manage client-authorized security assessment projects, scopes, runs, and findings. |
| `felix operator [options]` | Launch the browser-based curation console on strict loopback (`127.0.0.1`). |
| `felix config [subcommand]` | View and manage persistent defaults in `~/.felix/config.json`. |
| `felix doctor [options]` | Validate binary integrity, Go runtime, network stack, and permissions. |
| `felix version` | Display Felix version, platform architecture, and compiler details. |
| `felix update [options]` | Check for or install verified updates from official GitHub releases. |
| `felix install` | Register the Felix executable in the user system PATH. |
| `felix uninstall` | Remove the Felix executable from the user system PATH. |
| `felix completion [shell]` | Generate native shell autocompletion (PowerShell, Bash, Zsh, Fish). |
| `felix help [command]` | Display usage instructions and flag options. |

> For comprehensive command-by-command instructions, detailed flag references, and hands-on testing exercises, see the **[CLI Learning Guide](docs/cli/README.md)**.

### Scan Controls
- `--timeout, -t <duration>`: Request timeout per target (e.g. `10s`, `30s`, `1m`) [default: `10s`].
- `--concurrency, -c <int>`: Number of concurrent workers [default: `10`].
- `--scope <mode>`: Scope boundary (`same-origin`, `subdomains`, `explicit`) [default: `same-origin`].
- `--max-assets <int>`: Upper bound on assets crawled/ingested.
- `--max-response-size <size>`: Maximum response byte limit (e.g. `5MB`, `10MB`, `512KB`) [default: `10MB`].
- `--export <file>`: Output assessment report (`report.html`, `report.json`, or `report.sarif`).
- `--json [file]`: Save or output machine-readable scan result.
- `--sarif [file]`: Export OASIS SARIF 2.1.0 standard report for CI/CD security scanning.
- `--user-agent <string>`: Custom HTTP User-Agent header string.
- `-l <file>`: Read target URLs from a line-separated file.
- `--quiet, -q, --silent, -s`: Suppress progress output and ASCII banners.
- `--verbose, -v`: Display operational scan parameters and discovered asset inventory.

---

## Assessment States & Reachability Handling

FELIX deterministically classifies every assessment into one of four states:

- **`COMPLETED`**: Target and discovered assets were successfully audited without fatal error. Overall Risk Score (0–100) is fully computed and attributed.
- **`PARTIAL`**: Primary target was reachable, but secondary asset fetches encountered non-fatal errors (e.g. 404, timeouts on individual bundles). Findings and risk score reflect completed analysis.
- **`BLOCKED`**: Target is unreachable due to deterministic environmental errors (DNS failure, TCP connection refused, TLS handshake failure). Assessment halts immediately; Risk Score is reported as **`N/A`** (`--`); Exit code: `2`.
- **`FAILED`**: Target request failed due to total network timeout or connection reset. Assessment halts immediately; Risk Score is reported as **`N/A`** (`--`); Exit code: `2`.

---

## Exit Code Contract

Felix enforces deterministic Unix exit codes suitable for automation and CI/CD pipelines:

- **`0` (Clean / Informational):** Scan completed successfully with zero actionable findings (or informational observations only).
- **`1` (Actionable Findings):** Scan identified security conditions requiring review (Low, Medium, High, or Critical severity).
- **`2` (Usage / Runtime Error):** CLI syntax error, invalid arguments, conflicting flags (`--quiet` + `--verbose`), or unreachable target.

---

## License

Felix is licensed under the [MIT License](LICENSE).
