# FELIX CLI :: Comprehensive Command-by-Command Learning Guide

> **Deterministic Web Security Auditing Platform**  
> *"Attackers rely on luck. Felix leaves them zero."*

Welcome to the comprehensive command-by-command learning and verification guide for the **FELIX** security assessment CLI.

This documentation suite is organized for security engineers, auditors, penetration testers, and contributors who need to understand, verify, and test every command, subcommand, flag, exit code, error condition, and assessment state in the FELIX platform.

---

## Guide Structure

The guide is divided into 7 focused modules:

| Guide | Title | Purpose & Coverage |
| :--- | :--- | :--- |
| **[01-command-inventory.md](01-command-inventory.md)** | **Command Inventory & Exit Codes** | Exhaustive index of all 12 registered commands, argument signatures, and the Unix exit code contract (`0`, `1`, `2`). |
| **[02-global-flags.md](02-global-flags.md)** | **Global Flags & Dispatch Architecture** | CLI root dispatcher, `--help`, `--version`, verbosity hierarchy (`--quiet` vs `--verbose`), and flag conflict enforcement. |
| **[03-scan.md](03-scan.md)** | **Audit & Scan Engine (`felix scan`)** | Target auditing, timeout, concurrency, scope modes, response size limits, reachability classification, SARIF export, and test scenarios. |
| **[04-report.md](04-report.md)** | **Zero-Network Reporting (`felix report`)** | Offline HTML (Pure-Black Mode), JSON, and SARIF 2.1.0 generation from saved scan results; risk recalculation and score reconciliation. |
| **[05-client-and-assessment.md](05-client-and-assessment.md)** | **Enterprise Platform (`client` & `assessment`)** | Client profiles, structured assessment projects, fail-closed authorization, scope rules, exclusion precedence, and multi-module auditing. |
| **[06-operator-and-doctor.md](06-operator-and-doctor.md)** | **Operator Console & Diagnostics (`operator` & `doctor`)** | Strict loopback-bound web curation console (`127.0.0.1`), runtime readiness checks, and Authenticode trust verification. |
| **[07-system-commands.md](07-system-commands.md)** | **System & Configuration Utilities** | Persistent defaults (`config`), atomic cryptographically verified updates (`update`), PATH integration (`install`/`uninstall`), and autocompletion (`completion`). |

---

## Core Safety Rules for Learning and Testing

When learning and testing FELIX CLI commands:

1. **Authorized Scope Only:**
   - Never run `felix scan` or `felix assessment run` against third-party production targets without explicit, verifiable written authorization.
   - Use locally hosted testbeds (e.g. OWASP Juice Shop on `http://127.0.0.1:3000`) or safe loopback synthetic test harnesses.
2. **Deterministic Non-Destructive Operation:**
   - FELIX is strictly non-destructive by design: it never executes SQL injection payloads, never executes XSS payloads, never fuzzes with destructive mutations, and never submits HTML forms.
3. **Assessment Gating:**
   - FELIX enforces a strict **fail-closed** policy for structured assessments: scans will refuse to execute if authorization has not been granted, is pending, has expired, or has been revoked.
4. **Offline Reporting Guarantee:**
   - `felix report` executes with **zero outbound network requests**. You can safely generate reports in isolated environments or air-gapped systems.

---

## Quick Navigation

```text
felix
├── scan          ─── Target Auditing & Exposure Detection
├── report        ─── Zero-Network Report Rendering (HTML/JSON/SARIF)
├── client        ─── Client Profile & Organization Management
├── assessment    ─── Enterprise Project Scoping, Authorization & Execution
├── operator      ─── Loopback-Only Web Curation & Delivery Console
├── doctor        ─── Environment, Network, & Security Diagnostics
├── config        ─── Persistent CLI Defaults (~/.felix/config.json)
├── update        ─── Cryptographic Release Verification & In-Place Update
├── install       ─── User PATH Registration
├── uninstall     ─── User PATH Removal
├── completion    ─── Shell Autocompletion (PowerShell, Bash, Zsh, Fish)
└── version       ─── Binary Version & Compiler Metadata
```
