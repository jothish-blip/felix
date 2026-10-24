# Felix Limitations & Non-Goals

An honest, transparent assessment of technical boundaries, non-goals, and operating limitations is essential for any serious security auditing tool. This document outlines what Felix cannot determine and the fundamental boundaries of its black-box auditing model.

---

## 1. No Guarantee of Absence

> [!WARNING]
> **A clean Felix scan does not prove that a target application is free of vulnerabilities.**

Felix evaluates client-accessible attack surfaces, client-side JavaScript bundles, and exposed endpoints. A scan with zero findings indicates that no security weaknesses matching Felix's current detection patterns were observed under the specified scope. It does not establish the total absence of security defects, architecture flaws, or zero-day vulnerabilities.

---

## 2. Black-Box Boundary Limitations

Felix operates exclusively from an external, black-box perspective:
- **No Internal Source Code Access:** Felix inspects public client bundles (HTML, JS, CSS). It does not analyze server-side source code (Node.js, Go, Python, Java, PHP), internal microservices, or database schemas.
- **No Server Infrastructure Visibility:** Felix cannot observe server operating system hardening, kernel patch levels, internal network firewalls, or VPC segmentation.
- **No Internal Cloud Configuration Visibility:** Felix cannot audit AWS IAM roles, Google Cloud IAM bindings, or private cloud configurations that are not exposed over public HTTP endpoints.

---

## 3. Authentication & Session Limitations

Felix operates primarily as an **external auditor**:
- **Default Unauthenticated Crawling:** By default, `felix scan` crawls and assesses targets without maintaining authenticated user sessions.
- **Declarative Multi-Tenant Profiles:** While Felix supports multi-tenant BOLA/IDOR assessment via declarative profile configurations (`felix.target.yml` via `--profile` and `--cross-tenant`), it requires operator-supplied credentials injected through environment variables (`FELIX_AUTH_*`). Felix does **not** perform automated account registration, credential guessing, or brute-force authentication.
- **No Privilege Escalation Fuzzing:** Felix does not attempt automated vertical privilege escalation (user to root/admin) through exploit payload injection.
- **Session Management Auditing:** Felix does not evaluate session token entropy, server-side session revocation, or concurrent login restrictions.

---

## 4. Dynamic Single Page Application (SPA) Limitations

Felix relies primarily on pure-Go static HTML tokenization and lexical JavaScript bundle route extraction:
- **No Embedded Browser Engine:** Felix embeds **no browser runtime, Chromium binary, Node.js, or Playwright engine**.
- **Optional External Driver:** While `pkg/crawler` provides an optional `HeadlessBrowserDriver` capable of invoking an operator-installed external Chromium/Chrome/Edge binary when programmatically configured in Go library code, dynamic browser discovery is disabled by default (`opts.Enabled = false`) and no CLI flag exists on `felix scan`.
- **Runtime-Constructed Endpoints:** Endpoints assembled dynamically through complex runtime concatenation, string manipulation, or external API responses may evade static extraction unless an external browser driver is explicitly configured.
- **Client-Side State Flaws:** Vulnerabilities dependent on complex client-side state transitions, local storage manipulation, or DOM XSS cannot be confirmed without dynamic runtime execution.
- **WebSockets and gRPC-Web:** Real-time bidirectional WebSocket connections and binary gRPC channels are not currently audited.

---

## 5. Secret Detection Limitations

- **Heuristic Candidates (`NOT_VERIFIED`):** High-entropy strings are mathematical candidates, not confirmed live credentials. They require human engineering review to verify whether they represent production keys, test tokens, or benign hashes.
- **Split or Obfuscated Secrets:** Credentials that have been split across multiple variables, encrypted client-side, or injected via backend server-side rendering (SSR) will not be detected.
- **Server-Side Environment Variables:** Secrets stored properly in server environment variables (e.g. `process.env.DB_PASSWORD`) and never referenced in client code are invisible to Felix.

---

## 6. Cloud, BaaS & Database Verification Boundaries

- **Bounded Non-Destructive Probing:** Felix checks for unauthenticated public exposure (e.g., Supabase tables with RLS disabled, public Firebase `/.json`). It cannot evaluate complex Row Level Security policies that grant unauthorized access based on custom JWT claims.
- **Private Cloud Infrastructure:** Private S3 buckets, internal VPC endpoints, and IAM-restricted resources will correctly return HTTP `403 Forbidden` and be marked `NOT_EXPOSED`. Felix cannot evaluate whether internal users possess excessive permissions.
- **Database Protocol Boundaries:** Felix conducts minimal wire-level protocol reachability handshakes (MongoDB BSON `isMaster`, Redis `PING`, PostgreSQL `StartupMessage`, MySQL handshake) and evaluates HTTP management surfaces (Elasticsearch REST, PostgREST, Hasura, Mongo Express). Felix intentionally does **not** execute invasive SQL injection fuzzing, credential brute-forcing, or raw database dumps.

---

## 7. Business Logic & Complex Workflows

Felix is designed to detect configuration weaknesses, client exposures, and API surface vulnerabilities. It cannot audit:
- Multi-step business logic flaws (e.g. coupon stacking, negative price manipulation, transaction replay)
- Race conditions (e.g. double-spending)
- Workflow bypasses (e.g. skipping payment checkout steps)
- Semantic input validation bugs specific to application business rules

---

## 8. False Positives & False Negatives

Neither false positives nor false negatives can be mathematically eliminated in automated security testing:
- **False Positives:** While Felix's verification model aggressively filters benign patterns and checks response codes, novel development frameworks or non-standard HTTP response semantics may occasionally lead to misclassified observations.
- **False Negatives:** Endpoints hidden behind unreferenced routes, non-standard HTTP methods, or obscure headers may not be discovered during a standard crawl.

Felix is designed to be a high-signal component of an in-depth defensive security program, alongside code review, authenticated penetration testing, and threat modeling.

---

## 9. Platform Code Signing & Operating System Trust

Operating system application reputation is governed by external operating system policies:
- **Windows SmartScreen Reputation:** Microsoft Defender SmartScreen evaluates binary and certificate reputation over time. Newly released versions may initially trigger SmartScreen reputation warnings until download volume and reputation accrue across the Windows user base, regardless of whether binaries are Authenticode-signed. Felix never attempts to disable, bypass, or circumvent Windows security protections.
- **Local Development Certificate Scope:** The free local development trust path (`scripts\setup-dev.ps1` and `scripts\install-dev-trust.ps1`) signs binaries with a dedicated development certificate trusted exclusively on the local machine where the developer explicitly installs it. It is explicitly labeled for DEVELOPMENT / TESTING ONLY and does not confer public SmartScreen reputation.
- **macOS Gatekeeper Notarization:** macOS requires Apple Developer ID signing and Apple notarization tickets for binaries distributed outside the App Store. When binaries are installed manually without Apple signing credentials configured in CI/CD, macOS marks the binary with the `com.apple.quarantine` extended attribute, requiring operator quarantine clearance (`xattr -d com.apple.quarantine`).
- **Linux Distribution Verification:** On Linux, trust is established cryptographically through published SHA-256 digests and source-available reproducibility, rather than operating system certificate trust stores.
- **APT Repository Signing Key Exposure (Phase 12.10 Blocker):** The private OpenPGP key `scripts/packaging/keys/apt-signing-key.priv.asc` was committed to repository history (`f8f2f59d90fb3d02a4664c357e87f7528d3677ab`). External APT repository distribution is paused. Debian/Ubuntu/Kali operators must verify `.deb` packages via published SHA-256 digests and detached OpenPGP signatures (`SHA256SUMS.asc`) once rotated keys are deployed. Formal key revocation, secret provisioning, and Git history scrubbing remain an open release blocker for Phase 12.10.

---

## 10. Mobile (Android APK) Static Auditing Boundaries

Felix provides static inspection for Android APK archives (`pkg/apk`):
- **Static Analysis Only:** Felix extracts and analyzes the compiled `AndroidManifest.xml`, `classes.dex` bytecode strings, and asset files. It does **not** perform dynamic runtime analysis, sandbox execution, or memory inspection.
- **No Dynamic Instrumentation:** Felix does not spawn Android emulators, attach Frida/Xposed hooks, or perform runtime method tracing.
- **Obfuscation & Packing:** Severely obfuscated (e.g. ProGuard/R8, DexGuard) or commercial native-packed APKs may prevent discovery of hardcoded endpoints and string literals.
- **No Live Traffic Interception:** Felix does not configure an in-line MITM proxy or test certificate pinning bypasses dynamically against a running device.

---

## 11. Modern API Specification & Probing Boundaries

Felix evaluates modern API architectures and OpenAPI/Swagger specifications:
- **Spec vs. Live Delta:** Felix reconciles declared endpoints against client bundles and live responses. Undocumented internal endpoints that are never referenced in client code or specs cannot be identified without invasive wordlist fuzzing (which Felix strictly does not do).
- **Non-Destructive Safe Probing Only:** When `--probe-live` (or `--probe`) is enabled, probing is strictly confined to non-destructive read-oriented queries (`HEAD`, `OPTIONS`, `GET`). Felix **never** generates mutating payloads (`POST`, `PUT`, `DELETE`, `PATCH`, SQLi, or XML entity injection). However, read-oriented HTTP methods do not guarantee that every remote server is free of side effects; non-compliant backends may trigger state changes, process transitions, or alter session state upon receiving a `GET` request.
- **Classification & False Positive Boundaries:** Felix classifies endpoints as public, authenticated, or forbidden based on HTTP response status codes (200 vs 401 vs 403) and content heuristics. While probe classification filters out generic single-page-app HTML fallback shells, custom 404 pages, and transport anomalies against controlled fixtures, black-box probing cannot mathematically guarantee zero false positives or false negatives against non-standard production server architectures.
- **Dual-Identity BOLA Testing:** Default scans do not test parameter-level authorization bypasses across roles. Testing cross-tenant authorization requires explicit declarative target profiles (`--profile <file> --cross-tenant`) with operator-supplied credentials injected via environment variables.

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Security & Safety Controls](SECURITY.md)** — Non-destructive guarantees and scope controls.
- **[Contributing Guide](CONTRIBUTING.md)** — Development setup and pull request expectations.
