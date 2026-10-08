# Felix Security & Safety Controls

This document details the security principles, non-destructive design guarantees, operational safety boundaries, and sensitive data protections engineered into Felix.

---

## 1. Authorization Requirement

> [!IMPORTANT]
> Felix is an auditing tool designed exclusively for authorized defensive assessments, internal penetration testing, and security quality gates.

Users must obtain explicit authorization from system owners before auditing targets. Felix is engineered to operate strictly within authorized target scopes. Running security audits against systems without authorization may violate local laws and terms of service.

---

## 2. Non-Destructive Design Principles

Felix is strictly non-destructive:
- **Read-Only HTTP Operations:** Probing activities are limited to safe HTTP `GET` and `HEAD` requests. Felix **never** submits `POST`, `PUT`, `DELETE`, or `PATCH` payloads that alter application state or database records.
- **No Vulnerability Exploitation:** Felix does not inject SQL injection payloads, cross-site scripting (XSS) vectors, command injection strings, or deserialization exploits.
- **No Brute-Force Enumeration:** Felix does not execute dictionary attacks, credential stuffing, or aggressive directory wordlist fuzzing.
- **No Authentication Bypass:** Felix inspects access responses (e.g. 401 vs 403 vs 200). It never attempts to forge session cookies, tamper with JWT signatures, or bypass access controls.

---

## 3. Scope Boundary Enforcement

Felix strictly confines network activity to authorized targets using domain boundaries defined in `pkg/crawler/scope.go`:

| Scope Mode | Boundary Rule | Prohibited Requests |
| :--- | :--- | :--- |
| **`same-origin`** *(Default)* | Exact match on URI Scheme, Hostname, and Port (`https://app.example.com:443`). | Third-party CDNs, external APIs, and different subdomains. |
| **`subdomains`** | Target domain and any child subdomain (`*.example.com`). | Completely separate root domains or third-party cloud hosts. |
| **`explicit`** | Target domain plus an explicitly declared allowlist of hostnames. | Any host not present in the allowlist. |

External assets (e.g., scripts hosted on third-party CDNs like `cdnjs.cloudflare.com`) are inventoried as `[external / skipped]` without downloading their full contents when out-of-scope.

---

## 4. Resource Protection & Availability

To ensure Felix never causes performance degradation, denial of service (DoS), or server instability, the following safety caps are enforced:

### Bounded Concurrency
All network requests are channeled through bounded Go channel semaphores (`chan struct{}`). The worker pool is strictly capped by `--concurrency` (default: 10 workers). No uncontrolled goroutine spawning occurs.

### Context Timeouts
Every network dial, TLS handshake, and HTTP round-trip is bound by `context.WithTimeout` (default: 10 seconds). If a server hangs or throttles connections, the context cancels the request cleanly to free sockets.

### Response Size Caps
All HTTP body reads stream through `io.LimitReader(resp.Body, maxBytes+1)`. If an asset exceeds the configured `--max-response-size` (default: 10MB), reading terminates immediately with `ErrAssetTooLarge`. Felix will never exhaust host memory downloading unbounded files.

### Maximum Asset Ingestion Caps
The `--max-assets` flag places a hard ceiling on the number of assets queued, downloaded, or processed during discovery.

### Redirect Loop Protection
Felix's custom HTTP redirect handler tracks redirect depth and halts execution after 10 hops (`stopped after 10 redirects`), mitigating infinite redirection loops.

### Rate-Limit Backoff (HTTP 429)
When servers return HTTP `429 Too Many Requests`, Felix detects rate-limiting headers (e.g., `Retry-After`) and backs off to respect server constraints.

---

## 5. Sensitive Data & Token Handling

### Mandatory Secret Redaction
When Felix discovers potential credentials in client assets (e.g. Supabase keys, AWS access IDs, Stripe tokens), the values are immediately masked in memory. Raw secret values are **never**:
- Printed in terminal output
- Written in cleartext to JSON scan results
- Embedded in HTML reports
- Logged to disk

Values are consistently redacted (e.g., `sb_p****************ud_e` or `AKIA****************`).

### Zero Credential Transmission Policy
Felix adheres to a strict zero-transmission policy:
- **Discovered client secrets and API keys are strictly NEVER transmitted to external provider APIs.**
- Felix never attempts to authenticate to AWS, Stripe, GitHub, or OpenAI using discovered tokens.
- Secret candidates remain classified as `NOT_VERIFIED` static observations, requiring human engineer validation.

---

## 6. Offline Network Safety

Felix enforces a decoupled operational model:
- **Scanning (`felix scan`):** Performs network requests once to audit the target and saves the reusable result.
- **Reporting (`felix report`):** Reads existing scan result JSON and produces reports offline with **zero network activity**. No external CDN scripts, stylesheets, web fonts, or tracking pixels are fetched during report generation.

---

## 7. Trusted Updates & Supply-Chain Integrity

Felix's update subsystem (`pkg/update`) protects against software supply-chain threats:
- **Official GitHub Distribution Only:** Felix strictly restricts update downloads to official GitHub release infrastructure (`github.com/jothish-blip/felix` or authenticated GitHub CDN objects). Arbitrary remote URLs are rejected.
- **Cryptographic SHA-256 Verification:** Release packages are verified against the authoritative `SHA256SUMS` manifest before extraction. Tampered or corrupted archives are rejected immediately.
- **ZipSlip Path Traversal Defense:** The archive extraction engine strictly sandboxes every file path against directory traversal (`..`, root slashes, or volume names).
- **Staging & Pre-Execution Verification:** Extracted binaries undergo PE/ELF/Mach-O magic byte verification and a sub-process execution probe (`version` check) inside an isolated temporary directory before being copied to the user bin directory.
- **Atomic Replacement & Automatic Rollback:** The active executable is backed up prior to replacement. If file copying or post-install verification fails, the original binary is immediately restored.
- **No Background Telemetry:** Updates are evaluated exclusively on explicit user command (`felix update --check` or `felix update`). Felix does not execute background telemetry, analytics, or automated background processes.

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Boundaries of black-box scanning.
- **[Contributing Guide](CONTRIBUTING.md)** — Development setup and pull request expectations.
