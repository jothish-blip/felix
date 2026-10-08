# Felix Operator Usage Guide

This guide provides practical instructions for installing, configuring, running, and automating security audits with the Felix CLI.

---

## Installation

### Method 1: Automated Script Installation

#### Windows (PowerShell)
Run the PowerShell installer to build (if necessary), install to `%LOCALAPPDATA%\Felix\bin`, and register the directory in your User `PATH`:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

#### Linux & macOS (POSIX)
Run the POSIX installer to build and copy to `~/.felix/bin`, updating shell profile files (`~/.bashrc`, `~/.zshrc`):
```bash
chmod +x ./scripts/install.sh
./scripts/install.sh
```

### Method 2: Self-Installation via Felix Binary
Once compiled, Felix can install itself into your system PATH:
```bash
felix install
```

To remove the binary from your system PATH (preserving user configurations):
```bash
felix uninstall
```

### Method 3: Building from Source
Ensure you have Go 1.22 or newer installed:
```bash
git clone https://github.com/jothish-blip/felix.git
cd felix
go build -o bin/felix ./cmd/felix
```

---

## System Verification

### Diagnostic Health Check (`felix doctor`)
Validate runtime readiness, binary integrity, TLS stack, workspace write permissions, report generators, and PATH availability:
```bash
felix doctor
```

Example output:
```text
===========================================================
 FELIX :: System Diagnostic & Runtime Readiness
===========================================================

 [PASS]    Executable Integrity             : felix.exe (13859840 bytes)
 [PASS]    Runtime Environment              : windows/amd64 (8 CPUs, go1.27.0)
 [PASS]    Configuration Storage            : Defaults active (C:\Users\LENOVO\.felix\config.json)
 [PASS]    Workspace Write Permission       : Writable (C:\Jothish\felix)
 [PASS]    Network & TLS Stack              : TLS 1.2+ ready
 [PASS]    Report Generation Subsystem      : HTML (Black Mode) & JSON ready
 [PASS]    PATH Availability                : C:\Users\LENOVO\AppData\Local\Felix\bin in PATH

Result: PASS — Felix is operational.
```

### Version Information (`felix version`)
```bash
felix version
```

---

## Scanning Targets (`felix scan`)

### 1. Basic Audit
Audit a single web target using default parameters:
```bash
felix scan https://example.com
```

### 2. Multi-Target Batch Audit
Supply a file containing one target URL per line:
```bash
felix scan -l targets.txt
```

### 3. Export Assessment Reports (`--export`)
Generate an offline HTML or JSON report from a single audit:
```bash
# Export HTML assessment report
felix scan https://example.com --export report.html

# Export JSON assessment report
felix scan https://example.com --export report.json

# Export both HTML and JSON simultaneously
felix scan https://example.com --export report.html,report.json
```

### 4. Output Machine-Readable JSON (`--json`)
Export or pipe reusable JSON scan results:
```bash
# Save JSON scan result to an explicit file
felix scan https://example.com --json results.json

# Output valid JSON directly to stdout and save to scan-result.json
felix scan https://example.com --json
```

---

## Decoupled Offline Reporting (`felix report`)

To separate network scanning from report generation, use `felix report`. This command generates HTML or JSON reports from an existing scan result file with **zero network activity**:

```bash
# Step 1: Scan target and save raw JSON scan result
felix scan https://example.com --json scan-result.json

# Step 2: Generate HTML report offline at any time (0 network requests)
felix report scan-result.json --html assessment-report.html

# Step 3: Print terminal summary of existing scan result
felix report scan-result.json
```

---

## Scan Control Flags Reference

All scan control flags follow strict validation:

| Flag | Argument Syntax | Default | Description |
| :--- | :--- | :--- | :--- |
| **`--timeout`**, `-t` | `<duration>` (`10s`, `30s`, `1m`) | `10s` | Network timeout per target. Rejects `<= 0` with exit code `2`. |
| **`--concurrency`**, `-c` | `<int>` (positive integer) | `10` | Worker pool size. Rejects `<= 0` with exit code `2`. |
| **`--scope`** | `same-origin` \| `subdomains` \| `explicit` | `same-origin` | Domain boundary enforcement. Rejects unsupported values with exit code `2`. |
| **`--max-assets`** | `<int>` (positive integer) | unbounded | Maximum number of assets processed. Rejects `<= 0` with exit code `2`. |
| **`--max-response-size`** | `<size>` (`5MB`, `10MB`, `512KB`) | `10MB` | Maximum response byte limit per asset. Rejects `<= 0` with exit code `2`. |
| **`--export`** | `<file>` (`report.html`, `report.json`) | none | Export assessment report to file(s). Single scan execution. |
| **`--json`** | `[file]` | `scan-result.json` | Save machine-readable scan result as JSON (or output to stdout). |
| **`--quiet`**, `-q`, `-s` | *boolean flag* | `false` | Suppress human-readable progress, banners, and summary. Preserves exit codes. |
| **`--verbose`**, `-v` | *boolean flag* | `false` | Display operational parameters and asset inventory safely without token leakage. |
| **`-l`** | `<file>` | none | File containing target URLs (one per line). |
| **`--user-agent`** | `<string>` | Felix default | Custom HTTP User-Agent string. |

### Flag Conflict Handling
The `--quiet` and `--verbose` flags are mutually exclusive. Supplying both produces an error and terminates execution with exit code `2`:
```bash
felix scan https://example.com --quiet --verbose
# [-] error: --quiet and --verbose cannot be used together
# (Exit Code: 2)
```

---

## Configuration Management (`felix config`)

Felix stores persistent defaults in `~/.felix/config.json`. These settings are applied automatically to scans unless overridden by explicit CLI flags.

### CLI Flag Precedence
```text
CLI Flags > ~/.felix/config.json > Built-in Defaults
```

### View Configuration (`felix config show`)
```bash
felix config show
```

Example output:
```text
Felix Configuration (C:\Users\LENOVO\.felix\config.json):
  timeout:      10 seconds
  concurrency:  10 workers
  scope:        same-origin
  max_size_mb:  10 MB
  user_agent:   Mozilla/5.0 (compatible; Felix/1.0; +https://github.com/jothish-blip/felix)
```

### Get a Setting (`felix config get`)
```bash
felix config get timeout
# 10
```

### Set a Setting (`felix config set`)
```bash
# Update default timeout to 30 seconds
felix config set timeout 30

# Update default concurrency to 20 workers
felix config set concurrency 20

# Update default scope mode
felix config set scope subdomains

# Update default asset response size cap in MB
felix config set max_size_mb 20
```

### Display Configuration File Path (`felix config path`)
```bash
felix config path
# C:\Users\LENOVO\.felix\config.json
```

### Reset Defaults (`felix config reset`)
```bash
# Reset a specific key
felix config reset timeout

# Reset all keys to default
felix config reset
```

---

## Shell Autocompletion (`felix completion`)

Generate native autocompletion scripts for your shell:

### PowerShell
Add autocompletion to your current PowerShell session or profile (`$PROFILE`):
```powershell
felix completion powershell | Out-String | Invoke-Expression
```

### Bash
```bash
# Add to current session
source <(felix completion bash)

# Install permanently
felix completion bash > /etc/bash_completion.d/felix
```

### Zsh
```zsh
felix completion zsh > "${fpath[1]}/_felix"
```

### Fish
```fish
felix completion fish > ~/.config/fish/completions/felix.fish
```

---

## Exit Code Contract

Felix returns standard exit codes for integration into CI/CD security quality gates:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| **`0`** | **Clean / Informational** | Audit completed successfully. Zero findings with severity $\ge$ LOW. All findings are `INFO` or target is clean. |
| **`1`** | **Actionable Findings** | Audit detected actionable security findings requiring attention (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`). |
| **`2`** | **Usage / Runtime Error** | Invalid flag arguments, conflicting flags, missing target, unreadable files, or unreachable target. |

### CI/CD Pipeline Integration Example
```bash
#!/usr/bin/env bash
felix scan https://staging.internal.app --export staging-report.html --quiet
EXIT_STATUS=$?

if [ $EXIT_STATUS -eq 0 ]; then
    echo "Felix Security Audit Passed: No actionable vulnerabilities found."
elif [ $EXIT_STATUS -eq 1 ]; then
    echo "Felix Security Audit Failed: Actionable findings detected. Review staging-report.html."
    exit 1
else
    echo "Felix Scan Runtime Error: Please verify configuration or network accessibility."
    exit 2
fi
```

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview and quick start.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design, pipeline, and concurrency.
- **[Detection & Verification Model](DETECTION-MODEL.md)** — Evidence and verification states.
- **[Security & Safety Controls](SECURITY.md)** — Non-destructive guarantees and scope controls.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Boundaries of black-box scanning.
- **[Contributing Guide](CONTRIBUTING.md)** — Development setup and pull request expectations.
