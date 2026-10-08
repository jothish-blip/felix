# Felix v1.0.0 Release Notes

**Felix v1.0.0** is the first general availability release of Felix: a high-performance, evidence-first, non-destructive web application security auditor built in Go.

Felix examines client-side web assets, single-page application (SPA) bundles, API endpoints, cloud service configurations, security headers, CORS policies, and exposed secrets, correlating them into verified security stories and decoupled assessment reports.

---

## Highlights

- **Evidence-First Architecture**: Every finding is backed by explicit verification states (`VERIFIED`, `PROBABLE`, `UNVERIFIED`) and concrete evidence items with source references and SHA-256 hashes.
- **Strict Non-Destructive Operation**: Safe for staging and production auditing. Employs read-only HTTP discovery, passive AST/regex extraction, and bounded, low-volume verification checks with zero state-altering payloads.
- **Decoupled Offline Reporting**: Scans produce self-contained, machine-readable JSON scan results. Generate professional HTML assessment reports (terminal black theme) offline at any time with **zero network activity**.
- **Modern SPA & Endpoint Intelligence**: Discovers JavaScript bundles, maps client-side routes, extracts structured API endpoints, classifies them by sensitivity, and reasons about required authentication states.
- **Unified Risk Scoring & Deduplication**: Combines CVSS-aligned base impact, active exploitability factors, asset criticality, and verification weight while deduplicating correlated symptoms into coherent security narratives.
- **Zero Runtime Dependencies**: Distributed as standalone, statically compiled native binaries for Windows, Linux, and macOS. Requires no Go runtime, Python, Git, or external package managers.
- **Built-In Diagnostics & Self-Management**: `felix doctor` validates system health and environment readiness; `felix install` / `felix uninstall` provides zero-friction PATH management.

---

## Release Artifacts & Checksums

All official binary artifacts are cryptographically hashed and published to GitHub Releases:
[https://github.com/jothish-blip/felix/releases/tag/v1.0.0](https://github.com/jothish-blip/felix/releases/tag/v1.0.0)

| Platform | Architecture | Archive | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **Windows** | x86_64 (`amd64`) | `felix_1.0.0_windows_amd64.zip` | `a2d89bdfd47e9a1e4070528d79a05a0f7f793f1e891e3324253f916d0ee831a4` |
| **Linux** | x86_64 (`amd64`) | `felix_1.0.0_linux_amd64.tar.gz` | `aa0d64a56c137ec4829b45ce7f2c31fbcba72235f963861f536a97f1036ecb08` |
| **Linux** | ARM64 (`aarch64`) | `felix_1.0.0_linux_arm64.tar.gz` | `ca8c1e8c442b0262fe890bdf2d5570bee551a244625869b468aab89469050242` |
| **macOS** | Apple Silicon (`arm64`) | `felix_1.0.0_darwin_arm64.tar.gz` | `955aa9755a4e15989b64e13cb63b5898674c4ff7306be54dcc99af0e84741fe7` |
| **macOS** | Intel x86_64 (`amd64`) | `felix_1.0.0_darwin_amd64.tar.gz` | `4e63742c93fbf763e37eff90c4ae3581d6c1d7cfd38e79467191006bdd30dd47` |

### Raw Executables

| Platform | Architecture | Executable | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **Windows** | x86_64 (`amd64`) | `felix_windows_amd64.exe` | `7f1cd9f4b1f99e5d69d11ac1bf0078a745c8a09ae156e142466d610acf44dcf1` |
| **Linux** | x86_64 (`amd64`) | `felix_linux_amd64` | `b8ef907bb5db27bac3d4108901277b8c11278d5018e9dce5db617acc999677c3` |
| **Linux** | ARM64 (`aarch64`) | `felix_linux_arm64` | `5d6731d9133509687f4fb219723e89282e494f5787d38430789563b914509b62` |
| **macOS** | Apple Silicon (`arm64`) | `felix_darwin_arm64` | `14a53b60128082ace2ad50e853b8f8d2554cd200e3f7b0865e68f4d160dc081f` |
| **macOS** | Intel x86_64 (`amd64`) | `felix_darwin_amd64` | `ded7dca2330e85b1acf2636c5e93c8b7b733c3172dabdd6391b5bcc0d1f0ef6a` |

---

## Quick Start

### Windows (Zero Dependencies)
```powershell
# 1. Download & extract felix_1.0.0_windows_amd64.zip
# 2. Run automated installer:
powershell -ExecutionPolicy Bypass -File .\scripts\install\install.ps1

# 3. Verify in a new terminal:
felix version
felix doctor

# 4. Audit a web target:
felix scan https://example.com --export report.html
```

### Linux & macOS
```bash
# Extract and place in ~/.felix/bin
tar -xzf felix_1.0.0_linux_amd64.tar.gz
mkdir -p ~/.felix/bin
mv felix ~/.felix/bin/
export PATH="$HOME/.felix/bin:$PATH"

# macOS Gatekeeper unquarantine:
# xattr -d com.apple.quarantine ~/.felix/bin/felix

# Verify and scan
felix doctor
felix scan https://example.com --export report.html
```

---

## Command Reference

| Command | Purpose |
| :--- | :--- |
| `felix scan <url>` | Run security audit against target application |
| `felix scan -l <file>` | Batch audit targets from a newline-delimited file |
| `felix scan --export <path>` | Export assessment report to HTML or JSON |
| `felix scan --json [file]` | Save machine-readable scan result JSON |
| `felix report <file> --html <out>` | Generate HTML assessment report offline (0 network requests) |
| `felix doctor` | Validate runtime readiness, executable integrity, and PATH status |
| `felix version` | Display semantic version, commit hash, build time, and architecture |
| `felix install` / `uninstall` | Register or remove Felix from user PATH |
| `felix config` | Manage persistent configuration defaults |
| `felix completion <shell>` | Generate shell autocomplete scripts (powershell, bash, zsh, fish) |

---

## Scope & Operational Safety

Felix guarantees non-destructive auditing:
- **Scope Modes**: `same-origin` (default), `subdomains`, and `explicit`. All out-of-scope URLs are strictly skipped during crawling.
- **Bounded Concurrency & Rate Limiting**: Tunable worker pool (`--concurrency`, default 10) and network timeout (`--timeout`, default 10s).
- **Zero Exploit Payloads**: Felix never injects fuzzing payloads, brute-forces directories, or performs credential stuffing.
- **Sensitive Token Masking**: All extracted API keys and tokens are masked in logs and reports.

For full architectural details, consult the [Architecture Guide](ARCHITECTURE.md) and [Security Model](SECURITY.md).
