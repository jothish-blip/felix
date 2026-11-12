# FELIX PHASE 10A — AUTHORIZED PILOT ONBOARDING & EXECUTION READINESS REPORT

**Project:** FELIX — Security Assessment & Vulnerability Intelligence Platform  
**Repository:** `C:\Jothish\felix`  
**Platform:** Windows 11 / `windows/amd64` (`go1.27.0`, `CGO_ENABLED=0`)  
**Git State:** Branch `main`, Commit `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9`  
**Build Version / Release:** `1.0.0` (`FELIX-1.0-Phase10A-Ready`)  
**Binary SHA-256 ([felix.exe](file:///C:/Jothish/felix/felix.exe) & [bin/felix.exe](file:///C:/Jothish/felix/bin/felix.exe)):** `sha256:d1f6e83e0127d240bc13e4ddcb785a8c8bc475a16870560530de207dc9348bc2` (`32,551,424` bytes)  
**Phase 10A Readiness Classification:** **`A. READY FOR AUTHORIZED PILOT ONBOARDING`**  
**Current Live Pilot Campaign Status:** **`BLOCKED`** *(Fail-closed as designed: `0` external targets provided, `0` external requests sent)*  
**Current Public Distribution Status:** **`BLOCKED`** *(Carried-forward Phase 9 P12.10 Authenticode & APT key blockers)*

---

## 1. Executive Summary

Phase 10A completed the full operational onboarding package, secondary authorization-gate audit, and offline readiness verification required before assessing FELIX's first owner-authorized external deployed application.

- **Secondary P0 Hardening Completed:** Auditing every network-capable entrypoint in [cmd/felix/main.go](file:///C:/Jothish/felix/cmd/felix/main.go) closed four remaining `--scope-manifest` / UTC-window gaps in `felix ci run`, `felix cve template run`, `felix apk --assess`, and `felix monitor snapshot/diff`, plus added missing `IsCurrentlyValid` and HTTP mid-window guard enforcement to `felix assessment businesslogic --run`.
- **Automated Pilot Readiness Checker Implemented:** Built `felix validate pilot-readiness` ([pkg/validation/readiness.go](file:///C:/Jothish/felix/pkg/validation/readiness.go)) performing 16 deterministic, zero-network checks across 6 explicit statuses (`READY`, `MISSING`, `INVALID`, `EXPIRED`, `NOT_CONFIGURED`, `BLOCKED`).
- **Full Go Test Suite Verified:** All `49/49` tested Go packages pass with `0` failures (`2` packages have `[no test files]`), and `go vet ./...` plus `go build ./...` exit `0`. Note: `CGO_ENABLED=0` prevented local `-race` execution, and `govulncheck` is not installed locally; both remain CI blockers for public release.
- **Strict Honesty Maintained:** Zero external HTTP requests were transmitted (`external_requests_sent: 0`). Because no owner-signed authorization contract, deployed target, credentials, or locked independent ground truth exist yet, running `felix validate pilot-readiness` against repository templates correctly reports `BLOCKED`. Real-world detection accuracy remains **unmeasured** until an authorized Phase 10 pilot executes.

---

## 2. Phase 2 Audit: Baseline Repository & Historical Evidence Check

All historical Phase 0–9 and Phase 10 artifacts were inspected and preserved intact:

- **Authorization & Campaign Templates ([test/evidence/phase8/realworld_readiness/](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/)):** Verified [authorization_contract_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/authorization_contract_template.json), [campaign_manifest_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/campaign_manifest_template.json), [ground_truth_registry_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ground_truth_registry_template.json), and [retest_expected_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/retest_expected_template.json) are non-executable templates with `confirmed: false` and `<REQUIRED: ...>` placeholders, and added matching unconfirmed templates [roles_config_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/roles_config_template.json) and [pilot_operator_checklist_template.md](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/pilot_operator_checklist_template.md).
- **Preserved Phase 10 Evidence:** Preserved [phase10_gate_refusal_proof.json](file:///C:/Jothish/felix/test/evidence/phase10/audit/phase10_gate_refusal_proof.json), [phase10_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase10/audit/phase10_verification_summary.json), [PHASE_10_FINAL_TECHNICAL_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_FINAL_TECHNICAL_REPORT.md), [PHASE_10_REAL_WORLD_ACCURACY_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_REAL_WORLD_ACCURACY_REPORT.md), and [PHASE_10_REMEDIATION_AND_RELEASE_HANDOVER.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_REMEDIATION_AND_RELEASE_HANDOVER.md).

---

## 3. Pilot Onboarding Package Specification

Before any pilot scan may run, the operator must collect and verify all three onboarding pillars below. **No mock values, placeholders, or scanner-derived entries are permitted.**

### A. Target & Authorization Requirements (Application Owner Supplied)

Every pilot campaign requires a signed `AuthorizationContract` / `CampaignManifest` containing:

| Field | Mandatory Requirement |
| :--- | :--- |
| `authorization.authorizing_party` | Legal organization / application owner name (no `<REQUIRED...>` or `example` placeholders) |
| `authorization.signed_by` | Named approving executive or asset owner |
| `authorization.authorization_ref` | Executed Statement of Work, Bug Bounty scope ID, or signed Authorization Ticket reference |
| `authorization.confirmed` | Boolean `true` — hard fail-closed requirement (`contract.confirmed is false` refuses all active/recon CLI entrypoints with exit code `2`) |
| `target_url` & `authorization.authorized_targets` | Exact scheme (`https://` preferred), hostname, and explicit port if non-standard; must pass `ValidateExternalTargetOrigin` (public or owner-approved staging DNS; loopback/private IPs remain blocked by default unless explicitly permitted) |
| `authorization.excluded_paths` / `excluded_urls` / `excluded_hosts` | Sensitive/destructive routes (`/admin/reset`, `/admin/shutdown`, `/billing/charge`, `/logout`, third-party SaaS origins, payment gateways, health-mutating endpoints) explicitly blocked before crawl, redirect, or active probes |
| `authorization.window_start` / `window_end` | Valid UTC RFC3339 testing window (`window_start < window_end`; current UTC must fall strictly inside `[window_start, window_end]` both at start and on every HTTP round-trip via `wrapWindowGuard`) |
| `blind_execution` | Must be `true` for accuracy validation campaigns |
| `allow_state_changing` | Keep `false` for staging/shared external pilots unless written agreement covers isolated synthetic mutation controls |
| **Approved Identities & Rate Bounds** | Separate dedicated test accounts (`user_a`, `user_b`, and optional `admin`) supplied via `--roles-config roles.json` (private `0600` permissions, never embedded in git/reports); configured request rate limit (`--rate-limit` / `-r`) and technical emergency contact for kill-switch coordination |

### B. Independent Ground-Truth Registry Specification (AppSec Reviewer Pre-Built)

To satisfy blind scientific evaluation (`derived_from_scanner: false`):

1. **Independence Rule:** Derived exclusively from source code review, OpenAPI/GraphQL specifications, authorization middleware audits, architecture docs, or manually reproduced pre-pilot advisories **without executing FELIX against the target**.
2. **Pre-Scan Timestamp & Cryptographic Lock:**
   - `established_at` UTC timestamp must strictly precede `executed_at` and current pilot launch UTC (verified automatically by check `[09] ground_truth_timestamp_precedence`).
   - `ground_truth_sha256` must be computed offline via `.\felix.exe validate hash-gt --ground-truth ground_truth.json` and pasted into `campaign_manifest.json` **before** running FELIX (enforced automatically by `felix validate verify-auth` and `felix validate pilot-readiness`).
3. **Minimum Balanced Control Design per Vulnerability Class (Pilot Benchmark Target):**
   - For reliable per-class accuracy (and closing Phase 9 external benchmark blocker), aim for `n >= 20` independent ground-truth controls per priority class where applicable:
     - **Confirmed Positive Controls (`expected_status: "VULNERABLE"`):** Genuine vulnerabilities verified manually from code/config/design.
     - **Negative Controls (`expected_status: "SECURE_NEGATIVE_CONTROL"`):** Intentionally hardened sibling endpoints (e.g., proper ownership middleware returning HTTP `403`, parameterized queries, strict CSP/CORS, HTML-encoded reflection) paired alongside vulnerable endpoints to measure specificity and false-positive rate.
     - **Out-of-Scope / Excluded Controls (`in_scope: false`, `expected_status: "OUT_OF_SCOPE"`):** Routes matching `excluded_paths` to prove FELIX never leaks requests outside scope.
     - **Configuration-Gated Entries (`requires_config`):** Explicitly tag entries needing `MULTI_ROLE`, `OAST`, or `BROWSER_DOM` so `NOT_CONFIGURED` is separated honestly from false negatives (`FN`).

### C. Privacy, Redaction, Storage & Emergency Stop Boundaries

| Operational Control | Enforced Mechanism in FELIX |
| :--- | :--- |
| **Credential & Secret Handling** | Pass tokens via `--roles-config roles.json` or env references rather than shell history where possible; `ReportRedactionClean` in [pkg/validation](file:///C:/Jothish/felix/pkg/validation) scans final JSON/HTML/SARIF reports to verify zero secret token/cookie leaks. Never store live credentials inside `test/evidence/` or `docs/`. |
| **Artifact File Permissions** | Pilot output directories and reports must use private `0600`/`0700` ACLs (checked by `output_directory_permissions` check `#14`). |
| **No Unauthorized Destructive Testing** | `allow_state_changing: false` keeps mutating BOLA/BFLA/BOPLA and retest state-changing endpoints non-destructive (`INCONCLUSIVE` on retest rather than mutating production/staging records). |
| **Out-of-Scope / 3rd-Party Isolation** | Same-origin policy (`--scope same-origin`), `CheckRedirect` target re-validation (`buildSafeRedirectPolicy`), and SSRF/link-local/loopback IP dialing guards prevent pivot onto internal metadata (`169.254.169.254`) or external third parties. |
| **Emergency Stop Conditions** | Immediately abort execution (`Ctrl+C`, revoke test tokens, notify owner contact) if target returns sustained `5xx`/availability degradation, an out-of-scope redirect occurs, testing approaches `window_end` UTC, or unexpected production data appears in HTTP responses. |

---

## 4. Standardized Pilot Campaign Directory Structure

A clean, credential-free campaign blueprint was created at [test/evidence/phase10/pilot_campaigns/TEMPLATE_CAMPAIGN/README.md](file:///C:/Jothish/felix/test/evidence/phase10/pilot_campaigns/TEMPLATE_CAMPAIGN/README.md):

```text
test/evidence/phase10/pilot_campaigns/<campaign_id>/
├── authorization_contract.json      # Signed owner authorization (confirmed: true, no secrets)
├── campaign_manifest.json           # Target, exclusions, UTC window, ground_truth_sha256 lock
├── ground_truth.json                # Independent pre-scan GT (derived_from_scanner: false)
├── retest_expected.json             # Expected remediation outcomes for post-patch retest
├── roles.config.json                # [LOCAL PRIVATE ONLY - GITIGNORED/NEVER COMMITTED]
├── preflight/
│   ├── pilot_readiness_check.json   # felix validate pilot-readiness --json output (0 requests)
│   └── verify_auth_output.txt       # felix validate verify-auth verification log (0 requests)
├── initial_run/
│   ├── assessment_report.json       # Blind initial FELIX JSON report
│   ├── assessment_report.html       # Initial HTML deliverable
│   ├── assessment_report.sarif      # Initial SARIF deliverable
│   └── authorization_summary.json   # Audited effective scope, identity roles & request counts
├── retest_run/
│   └── retest_report.json           # Post-patch live retest output
└── evaluation/
    ├── accuracy_eval.json           # felix validate evaluate 9-state confusion + Wilson CIs
    └── redaction_audit.json         # Verified zero secret leaks in deliverables
```

---

## 5. Readiness Classification Decision

- **Onboarding Framework Status:** **`A. READY FOR AUTHORIZED PILOT ONBOARDING`**
- **Live Campaign Execution Status:** **`BLOCKED`** *(Requires owner-signed contract, non-placeholder target, locked independent ground truth, and test identity tokens)*
- **Public Binary Release Status:** **`BLOCKED`** *(Requires Windows Authenticode signing, APT key remediation, CI `-race` + `govulncheck`, and completed external benchmark)*
