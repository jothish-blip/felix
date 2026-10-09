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

### Authentication Intelligence Safety & Zero-Probing Guarantees (`pkg/auth`)
Felix implements uncompromising safety rules for authentication auditing:
- **Zero Credential Probing:** Felix **never** performs dictionary attacks, password spraying, automated logins, or credential stuffing against login surfaces or API gateways.
- **Zero Form Submissions:** Discovered HTML `<form>` elements and login entrypoints are parsed strictly for structural intelligence; tests enforce `formSubmissionCount == 0`.
- **Zero Token Replay:** Discovered session cookies, bearer tokens, or OAuth authorization codes are **never** replayed or submitted to probe unauthorized endpoints or simulate account hijacking.
- **Strict Cookie Secret Redaction:** Cookie values are **never** stored in SQLite or written to reports. Only cookie metadata (name, domain, path, Secure, HttpOnly, SameSite, expiration) and defect observations are retained.
- **Header-Only Unverified Token Parsing:** Discovered JWT structures are base64-decoded strictly at the header level to evaluate declared algorithms (e.g. flagging `alg=none`), without storing token payloads or verifying against remote signers.

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

## 8. Windows Code Signing & Trust Architecture

Felix maintains a clear separation between local development testing and public production distribution:

### Local Development / Testing Path (Free & Machine-Scoped)
For local development, building, and testing without requiring cloud subscription expenses:
- **Dedicated Development Certificate:** A self-signed Authenticode certificate (`CN=Felix Development Code Signing, O=Felix Development, OU=Development Testing Only`) with Code Signing Enhanced Key Usage (`1.3.6.1.5.5.7.3.3`) is generated locally via `scripts\create-dev-cert.ps1`.
- **Explicit User Confirmation:** Trust is installed into the local machine or user trust store **only** after explicit operator confirmation via `scripts\install-dev-trust.ps1`.
- **Safe Scope:** The certificate is trusted **only on the specific machine** where installed. It does not possess authority outside the local test environment and cannot sign arbitrary software across other machines.
- **Idempotent Removal:** The development certificate can be cleanly and completely uninstalled at any time using `scripts\uninstall-dev-trust.ps1` with zero impact on other Windows certificates.
- **No Security Bypasses:** Felix strictly rejects disabling Windows Defender, modifying execution policies, or hacking SmartScreen. Trust is established purely through standard Windows Authenticode mechanisms.

### Public Production Distribution Path
- Public releases are authenticated cryptographically through SHA-256 manifests (`SHA256SUMS`) and machine-readable release metadata (`update.json`).
- Future production signing is configured via Microsoft Azure Trusted Signing / Apple Developer ID.
- Development certificates are never represented as commercial production authorities.

---

## 9. Assessment Authorization & Scope Enforcement Architecture

Felix 2.0 embeds formal security governance directly into the execution pipeline:

### Fail-Closed Authorization Enforcement
Felix strictly refuses to execute an assessment unless all authorization criteria are verified:
1. **Record Existence:** An explicit `authorizations` record must exist linked to the assessment.
2. **Status Approval:** Authorization status must be explicitly `APPROVED`. Records in `PENDING`, `EXPIRED`, `REVOKED`, or `NOT_RECORDED` states trigger an immediate **security refusal**.
3. **Temporal Validity Window:** If `valid_from` is defined, current time must be on or after `valid_from`. If `valid_until` is defined, current time must be on or before `valid_until`. Expired authorizations fail closed with zero network packets transmitted.

### Absolute Exclusion Precedence
Exclusion rules strictly override any broader scope allowances or approved targets:
- **Hostname Exclusions:** Exact hostnames (`internal.example.com`) or wildcards (`*.corp.example.com`) block matching assets, even when the parent domain is in-scope.
- **Path Prefix Exclusions:** Path boundaries (e.g. `/admin`, `/auth`, `/billing`) block endpoint analysis regardless of host origin.
- **Exact URL Exclusions:** Specific endpoints (e.g. destructive actions like `/logout` or session resets) are completely bypassed.
- **Pre-Execution Target Check:** If all approved targets are covered by active exclusion rules, execution fails closed before initiating connections.

### Redirect Sandbox Defense
When web targets return HTTP 301, 302, 307, or 308 redirects:
- Redirect destinations are validated dynamically against scope rules and exclusions.
- Redirects that escape the approved domain boundary are strictly halted.
- Redirects that navigate into excluded path prefixes are blocked immediately.

### Local Database Protection & Security
- **File Permissions:** The assessment database (`~/.felix/assessments.db`) and its directory are initialized with restricted permissions (`0700` directory / `0600` file) accessible only to the local operating user.
- **Zero Remote Telemetry:** Database records never leave the local environment; all assessments, targets, clients, and findings remain entirely offline.

---

## 10. Attack-Surface Discovery Safety & Zero-Exploitation Guarantees

Stage 2 introduces deep attack-surface intelligence with rigorous safety boundaries:

### Strict Zero Form Submission Guarantee
Felix statically parses HTML `<form>` tags, actions, HTTP methods, and input controls. Felix **strictly executes zero form submissions**.
- It does **not** simulate form POST or GET submissions.
- It does **not** trigger backend state modifications, account creations, password resets, or newsletter subscriptions.
- This invariant is strictly verified by unit and corpus test assertions ensuring `formSubmissionCount == 0`.

### Zero Credential Probing & Password Spraying Policy
Authentication surfaces (e.g. login gateways, registration endpoints, OAuth/OIDC handlers, MFA screens) are identified exclusively for structural inventory modeling.
- Felix **never** executes automated password guessing, dictionary attacks, or credential stuffing.
- Felix **never** tests default passwords or fuzzes authentication endpoints.
- Authentication endpoints remain structural inventory records and are never subjected to invasive brute-forcing.

### Safe Lexical JavaScript Analysis
Felix parses client JavaScript bundles and inline scripts using safe regex-based lexical scanners and static syntax patterns.
- No JavaScript code is executed in an engine or runtime.
- No headless browser or DOM execution environment is spawned.
- All extracted API keys and credential candidates are automatically sanitized (`[REDACTED_SECRET]`) in evidence fields.

### Scope Boundary Isolation for Attack Surface Assets
Every discovered asset (subdomain, API service, cloud bucket, third-party dependency) is evaluated against the assessment's approved scope rules:
- In-scope assets are flagged `in_scope = true`.
- External or unapproved assets (e.g. third-party CDNs, external analytics, unrelated apex domains) are strictly classified as `in_scope = false` with `status = OUT_OF_SCOPE`.
- Out-of-scope assets are completely excluded from active probing.

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Boundaries of black-box scanning.
- **[Contributing Guide](CONTRIBUTING.md)** — Development setup and pull request expectations.
