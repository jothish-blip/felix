# FELIX CLI :: Global Flags & Dispatch Architecture

> **Module 02** | Root CLI dispatcher, help mechanics, versioning, verbosity hierarchy, and flag conflict rules.

---

## 1. Dispatcher Architecture

FELIX uses a centralized, dependency-free command router in `cmd/felix/main.go`. When invoked:

```text
felix [command] [subcommand] [flags] [arguments]
```

1. **No Arguments:** Running `felix` with no arguments prints the platform banner, available commands, quick start snippets, and exits with code `0`.
2. **Help Flags:** Both `felix help`, `felix --help`, and `felix -h` are handled at the root and for every subcommand.
3. **Version Flags:** Both `felix version`, `felix --version`, and `felix -v` (at root level) dispatch to `runVersion()`.
4. **Command Routing:** If the first non-flag argument matches a registered command (`scan`, `report`, `client`, etc.), control passes to that command's runner.
5. **Unknown Command:** Returns error `[-] Unknown command "<name>"` followed by root usage and exits with code `2`.

---

## 2. Help System

FELIX supports contextual help for every command and subcommand:

```bash
# Root usage and command catalog
felix
felix help
felix --help
felix -h

# Contextual command help
felix scan --help
felix report --help
felix client --help
felix assessment --help
felix operator --help
felix config --help
felix doctor --help
felix update --help
felix completion --help
```

For subcommands with multiple actions (e.g. `client`, `assessment`), executing the command without arguments prints subcommand usage and flag options.

---

## 3. Versioning & Build Metadata

The `version` command inspects binary metadata injected at compile time:

```bash
felix version
```

### Sample Output:
```text
Felix Security Auditor
Version:      1.0.0
Build:        dev
OS:           windows
Architecture: amd64
Platform:     windows/amd64
Release:      GA Release
Compiler:     go1.27.0
```

### Build Injection Variables:
When compiled using `scripts/release/build.sh`, the following Go linker flags (`-ldflags`) are injected:
- `-X main.Version=<semver>`: Semantic version string.
- `-X main.GitCommit=<hash>`: Git short commit SHA.
- `-X main.BuildTime=<iso8601>`: UTC build timestamp.
- `-X main.Release=<Production|Development>`: Release channel designation.

---

## 4. Verbosity & Output Modes

FELIX provides two mutually exclusive operational output modes for audit commands:

### A. Quiet / Silent Mode
- **Flags:** `--quiet`, `-q`, `--silent`, `-s`
- **Behavior:** Suppresses ASCII art banners, progress spinners, intermediate endpoint logs, and human-readable summaries.
- **Use Cases:**
  - Automated CI/CD script execution where only the exit code matters.
  - Piping machine-readable JSON output directly to standard output or utilities like `jq`:
    ```bash
    felix scan https://example.com --quiet --json | jq .
    ```

### B. Verbose Mode
- **Flags:** `--verbose`, `-v`
- **Behavior:** Prints comprehensive operational details:
  - Exact target URLs, IP reachability status, and round-trip latency.
  - Full inventory of all discovered frontend assets, script bundles, and source maps.
  - Detailed findings metadata including confidence levels, verification status, and negative observation notes.
  - Real-time crawling progress and skipped out-of-scope URLs.

### C. Flag Conflict Enforcement
To prevent ambiguous logging states, **combining quiet and verbose flags is strictly forbidden**:

```bash
felix scan https://example.com --quiet --verbose
```
**Output:**
```text
[-] error: --quiet and --verbose cannot be used together
```
**Exit Code:** `2` (Runtime / Usage Error)

---

## 5. Practical Learning Exercises

### Exercise 2.1: Verify Root Help and Version
```powershell
# 1. Run root help
.\bin\felix.exe help

# 2. Check version
.\bin\felix.exe version

# 3. Check flag dispatch
.\bin\felix.exe --help
```

### Exercise 2.2: Test Flag Conflict Enforcement
```powershell
# Execute conflicting flags against a dummy target
.\bin\felix.exe scan https://example.com --quiet --verbose
# Verify exit code is 2
$LASTEXITCODE
```
*(Expected: Exit code 2, error message printed to stderr).*
