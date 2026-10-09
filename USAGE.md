# Felix Operator Usage Guide

This guide provides practical instructions for installing, configuring, running, and automating security audits with the Felix CLI.

---

## Installation & Distribution

Felix is distributed as self-contained, standalone native binaries with **zero runtime dependencies**. End users and operators do not need Go, Git, compilers, or developer tools.

### Option 1: Standalone Binary Release (Recommended)

Download the pre-compiled archive for your platform from the [GitHub Releases](https://github.com/jothish-blip/felix/releases):

| Platform | Architecture | Archive | Binary |
| :--- | :--- | :--- | :--- |
| **Windows** | x86_64 (`amd64`) | `felix_1.0.0_windows_amd64.zip` | `felix_windows_amd64.exe` (`felix.exe`) |
| **Linux** | x86_64 (`amd64`) | `felix_1.0.0_linux_amd64.tar.gz` | `felix_linux_amd64` (`felix`) |
| **Linux** | ARM64 (`aarch64`) | `felix_1.0.0_linux_arm64.tar.gz` | `felix_linux_arm64` (`felix`) |
| **macOS** | Apple Silicon (`arm64`) | `felix_1.0.0_darwin_arm64.tar.gz` | `felix_darwin_arm64` (`felix`) |
| **macOS** | Intel x86_64 (`amd64`) | `felix_1.0.0_darwin_amd64.tar.gz` | `felix_darwin_amd64` (`felix`) |

#### Windows Installation

Felix provides two installation options on Windows:

##### Path A: Local Development & Testing — FREE (No Azure / No Paid Certificates)
For developers and security analysts running Felix locally without requiring external cloud signing:
1. Run the all-in-one developer setup:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\setup-dev.ps1
   ```
2. The workflow:
   - Generates a dedicated **Felix Development Code Signing Certificate** (`CN=Felix Development Code Signing, O=Felix Development, OU=Development Testing Only`).
   - Prompts for explicit user confirmation to trust this certificate in your local `CurrentUser` store.
   - Signs `felix.exe` with standard Windows Authenticode.
   - Installs Felix to `%LOCALAPPDATA%\Felix\bin` and configures User `PATH`.
   - Verifies execution via `felix version` and `felix doctor --security`.

To remove the development trust at any time:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-dev-trust.ps1
```

##### Path B: Public Production Distribution (Official Releases)
1. Download `felix_1.0.0_windows_amd64.zip` from [GitHub Releases](https://github.com/jothish-blip/felix/releases).
2. Extract the archive.
3. Run the automated installer:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install\install.ps1
   ```
   *Alternatively, copy `felix.exe` to `%LOCALAPPDATA%\Felix\bin\felix.exe` and add `%LOCALAPPDATA%\Felix\bin` to your User `PATH`.*
4. Open a new terminal and verify:
   ```cmd
   felix version
   felix doctor
   ```

#### Linux Installation
1. Download and extract the archive for your architecture:
   ```bash
   tar -xzf felix_1.0.0_linux_amd64.tar.gz
   ```
2. Move the binary into your user bin directory:
   ```bash
   mkdir -p ~/.felix/bin
   mv felix ~/.felix/bin/
   ```
3. Add Felix to your `PATH` (in `~/.bashrc`, `~/.zshrc`, or profile):
   ```bash
   export PATH="$HOME/.felix/bin:$PATH"
   ```
4. Verify installation:
   ```bash
   felix version
   felix doctor
   ```

#### macOS Installation (Apple Silicon & Intel)
1. Download and extract the archive:
   ```bash
   # For Apple Silicon (M1/M2/M3/M4):
   tar -xzf felix_1.0.0_darwin_arm64.tar.gz

   # For Intel:
   tar -xzf felix_1.0.0_darwin_amd64.tar.gz
   ```
2. Move binary into user bin directory:
   ```bash
   mkdir -p ~/.felix/bin
   mv felix ~/.felix/bin/
   export PATH="$HOME/.felix/bin:$PATH"
   ```
3. Remove macOS Gatekeeper quarantine attribute:
   ```bash
   xattr -d com.apple.quarantine ~/.felix/bin/felix
   ```
4. Verify:
   ```bash
   felix version
   felix doctor
   ```

---

### Option 2: Self-Installation via Felix Binary
Once downloaded, Felix can automatically copy itself to the user bin directory and register itself in your user PATH:
```bash
# Windows / Linux / macOS
felix install
```

To cleanly uninstall the binary and remove it from your PATH:
```bash
felix uninstall
```

---

### Option 3: Clean Automated Uninstallation

#### Windows (PowerShell)
Run the dedicated uninstaller to remove the binary, delete the directory if empty, and cleanly purge the PATH entry without touching your configuration files or scan reports:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install\uninstall.ps1
```

#### Linux & macOS
```bash
rm -f ~/.felix/bin/felix
felix uninstall
```

---

### Option 4: Building from Source
Ensure you have Go 1.22 or newer installed:
```bash
git clone https://github.com/jothish-blip/felix.git
cd felix
go build -o bin/felix ./cmd/felix
```

---

### Upgrading Felix
To upgrade Felix:
1. Download the new release archive from [GitHub Releases](https://github.com/jothish-blip/felix/releases).
2. Run `powershell -ExecutionPolicy Bypass -File .\scripts\install\install.ps1` (Windows) or overwrite `~/.felix/bin/felix` (Linux/macOS).
3. Verify the updated version with `felix version`. Existing configurations in `~/.felix/config.json` and reports remain untouched.

---

### Common PATH & Environment Troubleshooting

| Symptom | Cause | Remediation |
| :--- | :--- | :--- |
| `'felix' is not recognized as an internal or external command` (Windows) | Current command prompt session has cached old `PATH` environment variable. | Close and restart your terminal or PowerShell session. Verify `%LOCALAPPDATA%\Felix\bin` is present in User PATH via `[Environment]::GetEnvironmentVariable("Path", "User")`. |
| `felix: command not found` (Linux/macOS) | `~/.felix/bin` is not in active shell `PATH`. | Add `export PATH="$HOME/.felix/bin:$PATH"` to `~/.bashrc` or `~/.zshrc` and run `source ~/.bashrc` (or `source ~/.zshrc`). |
| `scripts cannot be run because the execution policy is Restricted` (Windows) | PowerShell execution policy restricts unsigned local scripts. | Run with the bypass flag: `powershell -ExecutionPolicy Bypass -File .\scripts\install\install.ps1`. |
| `felix cannot be opened because the developer cannot be verified` (macOS) | macOS Gatekeeper quarantined the downloaded archive. | Clear quarantine flag: `xattr -d com.apple.quarantine ~/.felix/bin/felix` or `xattr -cr ~/.felix/bin/felix`. |
| Permissions Denied on Linux/macOS | Executable bit not set after extraction. | Run `chmod +x ~/.felix/bin/felix`. |


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

## Security Assessment Platform (`felix client` & `felix assessment`)

Felix 2.0 provides an enterprise-ready, client-authorized security auditing architecture with end-to-end relational traceability stored locally in an embedded SQLite database (`~/.felix/assessments.db`).

### 1. Client Management (`felix client`)

Manage client profiles and organizations:

```bash
# Add a client organization
felix client add --name "Acme Corp" --org "Acme Corporation Ltd" --contact-name "Alice Smith" --contact-email "alice@acme.example" --notes "Tier-1 Production Audit"

# List active clients (or include archived with --all)
felix client list [--all] [--json]

# Show detailed client dossier and associated assessments
felix client show <client-id-or-name>

# Archive a client
felix client archive <client-id-or-name>
```

### 2. Assessment Project Lifecycle (`felix assessment`)

The complete workflow enforces the principle:
`Client -> Authorization -> Approved Scope -> Assessment -> Execution -> Finding -> Evidence -> Report`

```bash
# Create assessment project (starts in DRAFT status)
felix assessment create --client "Acme Corp" --name "Q1 Web Security Audit" --target https://app.acme.example --scope-mode same-origin

# Show assessment dossier
felix assessment show <assessment-ref-or-id>

# Add secondary approved targets
felix assessment target add <assessment-ref> --url https://api.acme.example --notes "REST API Base"

# Add custom scope rules
felix assessment scope add <assessment-ref> --rule "subdomains:acme.example"

# Add strict exclusions (Exclusions strictly override any broader scope rule)
felix assessment exclude add <assessment-ref> --type HOSTNAME --pattern "billing.acme.example" --reason "PCI boundary"
felix assessment exclude add <assessment-ref> --type PATH_PREFIX --pattern "/admin" --reason "Out of test boundary"
felix assessment exclude add <assessment-ref> --type EXACT_URL --pattern "https://app.acme.example/logout" --reason "Session invalidation"

# Record explicit authorization (Transitions assessment from DRAFT to READY)
felix assessment authorize <assessment-ref> --authorizer "Jane Doe" --role "Head of Security" --reference "SEC-AUTH-2026-001" --valid-days 30

# Execute authorized assessment (Fails closed if unauthorized or expired)
felix assessment run <assessment-ref> [--concurrency 5] [--timeout 15s] [--max-assets 100] [--quiet] [--verbose]

# Inspect recorded findings with optional severity or verification filters
felix assessment findings <assessment-ref> [--severity HIGH] [--verification VERIFIED] [--json]

# List generated HTML and JSON report files
felix assessment reports <assessment-ref>

# Cancel an assessment project
felix assessment cancel <assessment-ref>
```

### 3. Fail-Closed Security Guarantees
- **No Authorization, No Audit:** If an assessment has no authorization record or its status is `PENDING`, `EXPIRED`, or `REVOKED`, `felix assessment run` exits immediately with a **security refusal** and performs **zero network requests**.
- **Exclusion Precedence:** Exclusions (`HOSTNAME`, `PATH_PREFIX`, `EXACT_URL`) are evaluated before any scope rule. Any target or URL matching an exclusion is strictly skipped.
- **Interrupted Run Recovery:** If a scan process crashes or is terminated abruptly, the store automatically recovers abandoned `RUNNING` executions on the next invocation, marking them `FAILED` and preserving partial findings.

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

## Secure Updates & Maintenance (`felix update`)

Felix features a built-in cryptographic updater that retrieves, validates, and installs official releases directly from GitHub.

### 1. Check for Available Updates (`--check`)
Query official release channels to see if a newer release is published without downloading or modifying local files:
```bash
felix update --check
```

Example output:
```text
[*] Checking for updates (current version: 1.0.0)...
Current version: 1.0.0
Latest version:  1.0.1

Update available. Run 'felix update' to upgrade.
Release details: https://github.com/jothish-blip/felix/releases/tag/v1.0.1
```

### 2. Perform Verified Self-Update (`felix update`)
Download the platform-specific release package, verify its SHA-256 digest against `SHA256SUMS`, stage and test the executable, and atomically apply the update:
```bash
felix update
```

Example output:
```text
[*] Starting Felix secure update (current: v1.0.0)...
 [CHECK   ] Querying official release channels...
 [RESOLVE ] Resolving platform distribution for windows/amd64...
 [CHECKSUM] Downloading SHA256SUMS verification manifest...
 [DOWNLOAD] Downloading felix_1.0.1_windows_amd64.zip (3.91 MB)...
 [VERIFY  ] Verifying SHA256 cryptographic digest...
 [EXTRACT ] Extracting verified release package...
 [STAGE   ] Validating extracted binary integrity...
 [INSTALL ] Applying atomic self-replacement...
 [DONE    ] Successfully updated Felix to v1.0.1

[+] Felix successfully updated to v1.0.1 (windows/amd64)
Run 'felix doctor' to verify system runtime readiness.
```

### 3. Update Options Reference

| Option | Argument Syntax | Purpose |
| :--- | :--- | :--- |
| **`--check`**, `-c` | *boolean flag* | Check for updates only; does not download archive or replace binary. |
| **`--version`**, `-v` | `<version>` (`1.0.1`) | Update or reinstall a specific release version. |
| **`--force`**, `-f` | *boolean flag* | Force reinstallation even if already on the target version or downgrading. |
| **`--dry-run`** | *boolean flag* | Download and verify release archive without replacing the running executable. |
| **`--repo`** | `<owner/repo>` | Override update source repository [default: `jothish-blip/felix`]. |

### 4. Integrity Verification & Atomic Rollback
Felix protects your installation through strict defensive controls:
- **HTTPS Only:** Updates are downloaded exclusively over TLS 1.2+ from official GitHub release infrastructure (`github.com/jothish-blip/felix` or verified GitHub CDN endpoints).
- **Cryptographic Hashing:** The archive is hashed and compared against the authoritative `SHA256SUMS` manifest before any files are unpacked.
- **ZipSlip Defense:** Archive extraction enforces destination sandboxing; any archive entry with `..`, absolute paths, or escaping prefixes is immediately rejected.
- **Pre-Install Execution Probe:** The extracted binary is tested in a temporary sandbox (`version` execution check) before replacing the active binary.
- **Atomic Replacement & Rollback:** On Windows, the running `.exe` is renamed to `.old` and the verified binary is copied into place. If the replacement or post-install verification fails, the original binary is automatically restored from backup.
- **No Silent Installs:** Automatic installation is disabled by default (`auto_install: false`). Updates are only installed upon explicit user command.

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
