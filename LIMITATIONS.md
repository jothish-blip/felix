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

Felix operates as an **unauthenticated external auditor**:
- **No Authenticated Scanning:** Felix does not maintain authenticated user sessions, submit login credentials, or test multi-role access control matrices.
- **No Privilege Escalation Testing:** Felix cannot verify vertical privilege escalation (user to administrator) or horizontal privilege escalation (user A to user B).
- **No Insecure Direct Object Reference (IDOR) Testing:** Verifying IDOR requires multi-tenant authenticated access tokens to compare authorization states, which Felix intentionally does not perform.
- **No Session Management Auditing:** Felix does not evaluate session token entropy, cookie lifecycle revocation, or concurrent login restrictions.

---

## 4. Dynamic Single Page Application (SPA) Limitations

Felix uses static HTML tokenization and regular-expression route extraction. It does **not** embed a headless browser (such as Chromium or Playwright) and does not execute JavaScript code at runtime:
- **Runtime-Constructed Endpoints:** Endpoints assembled dynamically through complex runtime concatenation, string manipulation, or external API responses may evade static extraction.
- **Client-Side State Flaws:** Vulnerabilities dependent on client-side state transitions, local storage manipulation, or DOM XSS cannot be confirmed without dynamic runtime execution.
- **WebSockets and gRPC-Web:** Real-time bidirectional WebSocket connections and binary gRPC channels are not currently audited.

---

## 5. Secret Detection Limitations

- **Heuristic Candidates (`NOT_VERIFIED`):** High-entropy strings are mathematical candidates, not confirmed live credentials. They require human engineering review to verify whether they represent production keys, test tokens, or benign hashes.
- **Split or Obfuscated Secrets:** Credentials that have been split across multiple variables, encrypted client-side, or injected via backend server-side rendering (SSR) will not be detected.
- **Server-Side Environment Variables:** Secrets stored properly in server environment variables (e.g. `process.env.DB_PASSWORD`) and never referenced in client code are invisible to Felix.

---

## 6. Cloud & BaaS Verification Boundaries

- **Bounded Non-Destructive Probing:** Felix checks for unauthenticated public exposure (e.g., Supabase tables with RLS disabled, public Firebase `/.json`). It cannot evaluate complex Row Level Security policies that grant unauthorized access based on custom JWT claims.
- **Private Cloud Infrastructure:** Private S3 buckets, internal VPC endpoints, and IAM-restricted resources will correctly return HTTP `403 Forbidden` and be marked `NOT_EXPOSED`. Felix cannot evaluate whether internal users possess excessive permissions.

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
- **macOS Gatekeeper Notarization:** macOS requires Apple Developer ID signing and Apple notarization tickets for binaries distributed outside the App Store. When binaries are installed manually without Apple signing credentials configured in CI/CD, macOS marks the binary with the `com.apple.quarantine` extended attribute, requiring operator quarantine clearance (`xattr -d com.apple.quarantine`).
- **Linux Distribution Verification:** On Linux, trust is established cryptographically through published SHA-256 digests and source-available reproducibility, rather than operating system certificate trust stores.

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Security & Safety Controls](SECURITY.md)** — Non-destructive guarantees and scope controls.
- **[Contributing Guide](CONTRIBUTING.md)** — Development setup and pull request expectations.
