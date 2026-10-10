# FELIX CLI :: System & Configuration Utilities

> **Module 07** | Persistent configuration, cryptographic updates, PATH integration, autocompletion, and versioning.

---

## 1. Persistent Configuration (`felix config`)

The `config` command manages persistent default settings stored in `~/.felix/config.json`. These defaults are automatically applied whenever CLI flags are omitted during scanning.

```bash
felix config <action> [arguments]
```

### Supported Actions:

| Action | Syntax | Description |
| :--- | :--- | :--- |
| **`show`** | `felix config [show]` | Display all current configuration settings and active file path. |
| **`get`** | `felix config get <key>` | Query the value of a specific configuration key. |
| **`set`** | `felix config set <key> <val>` | Persist a new value for a configuration key. |
| **`path`** | `felix config path` | Print the exact filesystem path to `config.json`. |
| **`reset`**| `felix config reset` | Reset all settings to factory defaults and remove `config.json`. |

### Available Configuration Keys:
- `timeout`: Network request timeout in seconds (positive integer, default: `10`).
- `concurrency`: Worker thread pool size (positive integer, default: `10`).
- `scope`: Default crawl scope (`same-origin`, `subdomains`, `explicit`, default: `same-origin`).
- `max_size_mb`: Max asset download limit in MB (positive integer, default: `10`).
- `user_agent`: Default HTTP User-Agent header string.
- `update_check`: Automatically check for release updates (`true`/`false`, default: `true`).
- `auto_install`: Automatically install updates (`true`/`false`, default: `false`).

---

## 2. Cryptographic Updater (`felix update`)

Felix includes an in-place updater designed to verify and install releases directly from official GitHub distribution channels:

```bash
felix update [options]
```

### Supported Options:
- `--check`, `-c`: Check if a newer version is published on GitHub without downloading or altering local files.
- `--version <semver>`: Install a specific release version (e.g. `1.0.1`).
- `--force`, `-f`: Force download and replacement even if already up to date.
- `--dry-run`: Download and verify package SHA256 without replacing the current binary.
- `--repo <owner/repo>`: Override update source (default: `jothish-blip/felix`).
- `--help`, `-h`: Show usage.

### Safety & Integrity Guarantees:
- **Cryptographic Hash Verification:** Every update package is checked against the authoritative `SHA256SUMS` manifest before extraction.
- **ZipSlip & Path Traversal Mitigation:** Archive unpacking validates target extraction paths.
- **Atomic Replacement & Rollback:** The new executable is validated in a sub-process test run. If replacement or execution fails, the previous binary is restored immediately.

---

## 3. PATH Installation (`felix install` & `felix uninstall`)

Felix provides built-in utilities to manage system PATH integration without requiring manual environment variable editing:

### Install (`felix install`)
- **Windows:** Copies the current binary to `%LOCALAPPDATA%\Felix\bin\felix.exe` and appends `%LOCALAPPDATA%\Felix\bin` to the User `PATH` environment variable.
- **POSIX (Linux/macOS):** Installs the binary into `~/.felix/bin/` and outputs PATH export recommendations.

### Uninstall (`felix uninstall`)
- Safely removes the installed binary and cleans up the PATH environment entry.
- **Data Preservation:** User databases (`~/.felix/assessments.db`), scan logs, and exported HTML/JSON reports are **preserved** and never deleted by uninstall.

---

## 4. Shell Autocompletion (`felix completion`)

Generate native autocompletion scripts for popular command shells:

```bash
felix completion <shell>
```

### Supported Shells:
- `powershell`
- `bash`
- `zsh`
- `fish`

### Installation Examples:

```powershell
# PowerShell (Current profile)
felix completion powershell | Out-String | Invoke-Expression
# Or persist in profile:
felix completion powershell >> $PROFILE
```

```bash
# Bash
felix completion bash > /etc/bash_completion.d/felix

# Zsh
felix completion zsh > ~/.zsh/completion/_felix

# Fish
felix completion fish > ~/.config/fish/completions/felix.fish
```

---

## 5. Practical Learning Exercises

### Exercise 7.1: View and Set Configuration
```powershell
# 1. View default configuration
.\bin\felix.exe config show

# 2. Update timeout to 15 seconds
.\bin\felix.exe config set timeout 15

# 3. Verify key query
.\bin\felix.exe config get timeout

# 4. Reset to default
.\bin\felix.exe config reset
```

### Exercise 7.2: Test Autocompletion Output
```powershell
# Generate and inspect PowerShell completion script
.\bin\felix.exe completion powershell | Select-Object -First 10
```

### Exercise 7.3: Check for Updates (Non-destructive)
```powershell
.\bin\felix.exe update --check
```
*(Expected: Queries official repository releases for available tags without altering binary).*
