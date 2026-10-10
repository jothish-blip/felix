# FELIX CLI :: Operator Console & Diagnostics (`operator` & `doctor`)

> **Module 06** | Local-first curation console, loopback security, runtime readiness, and security diagnostics.

---

## 1. Operator Console (`felix operator`)

The `operator` command launches the browser-based, local-first **Felix Operator Console**. It enables security consultants and lead auditors to review raw findings, curate commercial reports, and manage assessment delivery.

```bash
felix operator [options]
```

### Supported Options:

| Flag | Default | Description |
| :--- | :---: | :--- |
| `-host <string>` | `127.0.0.1` | Loopback IP to bind (strictly restricted to `127.0.0.1` or `::1`). |
| `-port <int>` | `8383` | TCP port for local HTTP listener. |
| `-operator-id <string>` | Current User | Identifier for the logged-in auditor session. |
| `-token <string>` | Auto-generated | Session authentication token for REST API calls. |
| `-db <string>` | `~/.felix/assessments.db` | Custom SQLite database file location. |
| `-no-open` | `false` | Do not automatically launch the default OS web browser. |

### Strict Loopback Security Boundary:
To protect sensitive client vulnerability dossiers from local network eavesdropping:
- Felix Operator **strictly refuses to bind to non-loopback interfaces** (e.g. `0.0.0.0`, LAN IPs, public interfaces).
- Binding to any host other than `127.0.0.1`, `localhost`, `::1`, or `[::1]` results in an immediate security refusal exit:
  ```text
  [-] Security refusal: Felix Operator Console must only bind to a loopback address (127.0.0.1 or ::1), got "0.0.0.0"
  ```

---

## 2. Runtime Diagnostics (`felix doctor`)

The `doctor` command performs non-destructive health and readiness diagnostics across the execution environment:

```bash
felix doctor [options]
```

### Supported Options:
- `--security`, `-s`: Run extended security, code-signing, and trust diagnostics.
- `--help`, `-h`: Show usage instructions.

### Diagnostic Verifications:
1. **Executable Integrity:** Validates binary existence, file size, and accessibility.
2. **Binary Signature:** Inspects Windows Authenticode signature status (reports signed vs. unsigned).
3. **Runtime Environment:** Reports OS, architecture, CPU count, and Go runtime version.
4. **Configuration Storage:** Checks `~/.felix/config.json` existence and read/write accessibility.
5. **Workspace Write Permissions:** Verifies that reports, temporary JSON files, and logs can be created in the current working directory.
6. **Network & TLS Stack:** Validates loopback resolution, DNS client availability, and TLS 1.2/1.3 capabilities.
7. **Report Subsystem:** Verifies that HTML report templates and JSON encoders initialize cleanly.
8. **PATH Availability:** Confirms whether the Felix executable resides in the user's system `PATH`.

---

## 3. Practical Learning Exercises

### Exercise 6.1: Run Standard Diagnostics
```powershell
.\bin\felix.exe doctor
$LASTEXITCODE
```
*(Expected: Output reports PASS across runtime, configuration, workspace, and network checks).*

### Exercise 6.2: Run Extended Security Diagnostics
```powershell
.\bin\felix.exe doctor --security
```
*(Expected: Displays detailed code-signing status and cryptographic certificate trust evaluation).*

### Exercise 6.3: Verify Operator Loopback Security Refusal
Test that non-loopback bindings are strictly rejected:
```powershell
.\bin\felix.exe operator -host 0.0.0.0 -no-open
$LASTEXITCODE
```
*(Expected: Immediate exit with code `2`, error indicates security refusal).*

### Exercise 6.4: Launch Operator Console in Headless Mode
```powershell
# Run with a 3-second timeout or launch briefly to confirm listener initialization
$job = Start-Job -ScriptBlock { & "C:\Jothish\felix\bin\felix.exe" operator --port 8383 --no-open }
Start-Sleep -Seconds 2
Receive-Job $job
Stop-Job $job
Remove-Job $job
```
*(Expected: Logs confirm `[+] Operator Session Active: • Listener: 127.0.0.1:8383 (Strict Loopback)`).*
