# FELIX CLI :: Enterprise Platform (`client` & `assessment`)

> **Module 05** | Relational assessment lifecycle, fail-closed authorization, scope exclusions, and multi-module auditing.

---

## 1. Relational Assessment Lifecycle

FELIX 2.0 introduces an enterprise assessment platform backed by an embedded SQLite database (`~/.felix/assessments.db`). It enforces complete relational traceability:

```text
┌──────────────┐     1:N     ┌────────────────┐     1:N     ┌─────────────────┐
│ Client Org   ├────────────►│ Assessment     ├────────────►│ Scope Rules &   │
│ (Metadata)   │             │ Project        │             │ Targets         │
└──────────────┘             └───────┬────────┘             └─────────────────┘
                                     │
                             1:1     ▼
                      ┌─────────────────────────┐
                      │ Explicit Authorization  │ (Fail-Closed Gate)
                      └──────────────┬──────────┘
                                     │
                             1:N     ▼
                      ┌─────────────────────────┐
                      │ Execution Runs          │
                      └──────────────┬──────────┘
                                     │
                             1:N     ▼
                      ┌─────────────────────────┐
                      │ Findings & Attack Paths │
                      └─────────────────────────┘
```

---

## 2. Managing Clients (`felix client`)

The `client` command manages registered organizations and contact identities:

```bash
felix client <subcommand> [flags]
```

### Subcommands:
- **`add`**: Register a new client organization.
  - `--name <string>` (Required): Client name or organization title.
  - `--org <string>`: Formal company / enterprise entity.
  - `--contact-name <string>`: Primary point of contact.
  - `--contact-email <string>`: Contact email address.
  - `--notes <string>`: Engagement notes or tier.
  - `--json`: Output newly created record as JSON.
- **`list`**: Display all active clients.
  - `--all`: Include archived clients.
  - `--json`: Output records in JSON.
- **`show <client-id>`**: Display full client profile and historical assessments.
- **`archive <client-id>`**: Safely archive client record.

---

## 3. Managing Assessments (`felix assessment`)

The `assessment` command orchestrates security engagements:

```bash
felix assessment <subcommand> [flags]
```

### Lifecycle Subcommands:
1. **`create`**: Initialize a new assessment project.
   ```bash
   felix assessment create --client "Acme Corp" --name "Q1 Security Audit" --target https://app.example.com --scope-mode same-origin
   ```
2. **`target add <asm-ref> --url <url>`**: Add secondary targets (e.g. API backend).
3. **`scope add <asm-ref> --rule <pattern>`**: Add explicit scope patterns (e.g. `subdomains:example.com`).
4. **`exclude add <asm-ref> --type <type> --pattern <pat> --reason <why>`**:
   - Types: `HOSTNAME`, `PATH_PREFIX`, `EXACT_URL`.
   - **Exclusion Precedence:** Exclusions strictly override targets and broader scopes. If `/admin` is excluded, no requests under `/admin` will ever be executed.
5. **`authorize <asm-ref> [flags]`**:
   - Flags: `--authorizer <name>`, `--role <title>`, `--reference <id>`, `--valid-days <n>`.
   - Transitions assessment from `DRAFT` to `READY`.
6. **`run <asm-ref> [flags]`**:
   - Flags: `--concurrency <n>`, `--timeout <duration>`, `--dry-run`.
   - **Fail-Closed Gate:** If authorization is missing, expired, or invalid, execution is strictly refused.
7. **`findings <asm-ref>`**: List all recorded findings linked to this assessment.
8. **`inventory <asm-ref>`**: Inspect cataloged attack surface assets (endpoints, forms, JS bundles).
9. **`reports <asm-ref>`**: List all generated assessment reports.
10. **`cancel <asm-ref>`**: Cancel an assessment.

### Specialized Inspection & Auditing Subcommands:
- **`auth <asm-ref>`**: Inspect discovered authentication surfaces, login forms, OAuth flows, and cookie attributes.
- **`authz <asm-ref> --policy <policy.json> --run`**: Assess API authorization boundaries (BOLA/IDOR, BFLA).
- **`apisec <asm-ref> --run`**: Audit against OWASP API Security Top 10 (2023).
- **`webvuln <asm-ref> --run`**: Assess web application vulnerabilities.
- **`sessionsec <asm-ref> --run`**: Inspect session lifecycle, token handling, and storage security.
- **`cloudsec <asm-ref> --mode external`**: Non-destructive cloud backend checks (AWS, Supabase, Firebase).
- **`businesslogic <asm-ref> --run`**: Analyze business logic workflows and state replay.
- **`correlate <asm-ref> --run`**: Correlate findings into attack paths.
- **`verify <asm-ref> --run`**: Verify empirical finding evidence.

---

## 4. Fail-Closed Security Policy

In enterprise environments, scanning unapproved systems carries severe legal and operational risks. FELIX implements fail-closed authorization:

| Condition | Assessment State | Result |
| :--- | :---: | :--- |
| No authorization recorded | `DRAFT` | Execution blocked: `[-] Refusing scan: unauthorized` |
| Authorization recorded, within valid days | `READY` / `APPROVED` | Execution permitted |
| Current date > authorization expiry | `EXPIRED` | Execution blocked: `[-] Refusing scan: authorization expired` |
| Explicit revocation recorded | `REVOKED` | Execution blocked: `[-] Refusing scan: authorization revoked` |

---

## 5. Practical Learning Exercises

### Exercise 5.1: Create Client and Assessment in Local SQLite
```powershell
# 1. Register a test client
.\bin\felix.exe client add --name "Test Labs Inc" --contact-email "sec@testlabs.invalid" --notes "Learning Sandbox"

# 2. List clients
.\bin\felix.exe client list

# 3. Create an assessment project
.\bin\felix.exe assessment create --client "Test Labs Inc" --name "Local Sandbox Audit" --target http://127.0.0.1:3000
```
Note the generated assessment reference ID (e.g. `ASM-2026-0001`).

### Exercise 5.2: Test Fail-Closed Refusal (Unapproved Scan)
```powershell
# Attempt to run without authorization
.\bin\felix.exe assessment run ASM-2026-0001
$LASTEXITCODE
```
*(Expected: Command fails immediately, refusing to scan because authorization has not been recorded).*

### Exercise 5.3: Authorize and Add Exclusions
```powershell
# 1. Add an exclusion rule
.\bin\felix.exe assessment exclude add ASM-2026-0001 --type PATH_PREFIX --pattern /internal --reason "Out of bounds"

# 2. Record explicit authorization
.\bin\felix.exe assessment authorize ASM-2026-0001 --authorizer "Alice Smith" --role "Head of Security" --reference "AUTH-SANDBOX-01" --valid-days 7

# 3. Inspect assessment dossier
.\bin\felix.exe assessment show ASM-2026-0001
```
*(Expected: Status transitions from DRAFT to READY, authorizer and exclusions visible in dossier).*
