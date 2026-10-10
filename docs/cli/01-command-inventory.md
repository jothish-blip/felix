# FELIX CLI :: Command Inventory & Exit Codes

> **Module 01** | Reference documentation of all registered commands, flags, and exit code contracts.

---

## 1. Registered Commands Matrix

FELIX registers 12 top-level commands plus the root `help` handler dispatched in `cmd/felix/main.go`:

| Command | Primary Action | Usage Syntax | State Persistence | Network Activity |
| :--- | :--- | :--- | :--- | :--- |
| `scan` | Run automated security audit on URL | `felix scan [flags] <target>` | Ephemeral / Export files | Outbound HTTP/HTTPS |
| `report` | Generate reports from scan JSON | `felix report <result.json> [flags]` | Output file (HTML/JSON/SARIF) | **Zero (Air-gapped)** |
| `client` | Manage organizations and clients | `felix client <subcommand> [flags]` | SQLite (`assessments.db`) | Local only |
| `assessment`| Manage enterprise assessment projects | `felix assessment <subcommand> [flags]` | SQLite (`assessments.db`) | Outbound when running |
| `operator` | Launch browser-based curation console | `felix operator [options]` | SQLite (`assessments.db`) | Local loopback only |
| `config` | View and modify persistent defaults | `felix config <action> [args]` | JSON (`~/.felix/config.json`)| Local filesystem |
| `doctor` | Runtime readiness & diagnostic checks | `felix doctor [options]` | None | Loopback/DNS check |
| `version` | Display version and compiler metadata | `felix version` | None | None |
| `update` | Check or install official binary releases| `felix update [options]` | Binary replacement | GitHub API & Releases |
| `install` | Add Felix binary to user system PATH | `felix install` | OS Environment (User PATH)| Local filesystem |
| `uninstall` | Remove Felix binary from system PATH | `felix uninstall` | OS Environment (User PATH)| Local filesystem |
| `completion`| Generate shell completion script | `felix completion <shell>` | Stdout | None |
| `help` | Display command usage and flags | `felix help [command]` | None | None |

---

## 2. Unix Exit Code Contract

FELIX enforces a strict, deterministic exit code convention across all commands, engineered for CI/CD gates, automation scripts, and containerized pipelines:

| Exit Code | Meaning | Condition Triggers |
| :---: | :--- | :--- |
| **`0`** | **Clean / Informational** | Assessment completed with zero actionable vulnerabilities (only `INFO` or clean assets discovered). Configuration updated, client created, or diagnostic checks passed without fatal failure. |
| **`1`** | **Actionable Findings Detected** | Assessment completed and discovered at least one actionable finding with severity `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Also returned by operational failures during database mutations or server runtime. |
| **`2`** | **Runtime / CLI Usage Error** | Syntax error, unrecognized flags, conflicting options (e.g. `--quiet` and `--verbose`), target unreachable (DNS failure, connection refusal, timeout), or unauthorized execution attempt. |

### Exit Code Evaluation in `scan`

The scan command determines exit codes as follows:

```text
Target Reachability Failure (Unreachable / DNS / Connection Refused) ──► Exit 2
CLI Flag Conflict (--quiet + --verbose)                            ──► Exit 2
Invalid Flag / Unknown Option                                      ──► Exit 2

Assessment COMPLETED / PARTIAL:
├── Findings count == 0                                            ──► Exit 0
├── Only INFO severity findings                                    ──► Exit 0
└── At least 1 finding of LOW, MEDIUM, HIGH, or CRITICAL           ──► Exit 1
```

---

## 3. Quick Command Reference

```bash
# 1. Quick Audit
felix scan https://example.com --export report.html --json scan.json

# 2. Offline Reporting (Zero Network)
felix report scan.json --html audit-report.html --sarif audit.sarif

# 3. Client & Assessment Project Management
felix client add --name "Acme Corp" --contact-email "security@acme.example"
felix assessment create --client "Acme Corp" --name "Q1 Audit" --target https://example.com
felix assessment authorize <asm-id> --authorizer "Jane Doe" --role "CISO"
felix assessment run <asm-id> --concurrency 5

# 4. Operator Console (Strict Loopback)
felix operator --port 8383 --no-open

# 5. System Diagnostics & Setup
felix doctor --security
felix config show
felix completion bash > /etc/bash_completion.d/felix
felix version
```
