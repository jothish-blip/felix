# FELIX PHASE 10A — OPERATOR EXECUTION RUNBOOK & RELEASE HANDOVER

**Project:** FELIX — Security Assessment & Vulnerability Intelligence Platform  
**Repository:** `C:\Jothish\felix`  
**Binary Under Handover:** [felix.exe](file:///C:/Jothish/felix/felix.exe) & [bin/felix.exe](file:///C:/Jothish/felix/bin/felix.exe) (`1.0.0`, `FELIX-1.0-Phase10A-Ready`, `32,551,424` bytes, `sha256:d1f6e83e0127d240bc13e4ddcb785a8c8bc475a16870560530de207dc9348bc2`)  
**Workspace Constraints:** Zero Git history changes committed/pushed; zero external scans executed (`0` requests).

---

## 1. Step-by-Step Operator Execution Runbook (15 Steps)

Execute steps **in strict numerical order** only after obtaining signed written owner authorization for an isolated/staging deployed target. Place all files under `test\evidence\phase10\pilot_campaigns\<CAMPAIGN_ID>\` (never commit `roles.config.json` or live session secrets).

| Step | Action & Exact PowerShell Command | Mandatory STOP Trigger |
| :-: | :--- | :--- |
| **1** | **Verify Signed Authorization Artifacts:** Confirm owner signed `authorization_contract.json` & `campaign_manifest.json` with `confirmed: true`, exact `authorized_targets`, `excluded_paths`, valid future/active UTC `[window_start, window_end]`, and technical kill-switch contact. | **STOP** if `confirmed` is not `true`, window is invalid, or target is shared production without explicit written approval. |
| **2** | **Verify Binary Integrity Hash:** `Get-FileHash .\felix.exe -Algorithm SHA256` and `.\felix.exe version`. | **STOP** if SHA-256 differs from recorded release build (`d1f6e83e0127d240bc13e4ddcb785a8c8bc475a16870560530de207dc9348bc2`). |
| **3** | **Prepare Campaign Workspace (`0700` Private):** Create `test\evidence\phase10\pilot_campaigns\<CAMPAIGN_ID>\` with `preflight\`, `initial_run\`, `retest_run\`, `evaluation\` subdirectories. | **STOP** if directory has world-readable/shared permissions. |
| **4** | **Build Independent Pre-Scan Ground Truth (`derived_from_scanner: false`):** AppSec reviewer documents `ground_truth.json` from code/OpenAPI/middleware BEFORE any FELIX scan runs (`VULNERABLE`, `SECURE_NEGATIVE_CONTROL`, `OUT_OF_SCOPE`, `requires_config`). | **STOP** if any entry is inferred from a FELIX output or `established_at` post-dates testing start. |
| **5** | **Compute Ground-Truth Lock SHA-256 Offline:** `.\felix.exe validate hash-gt --ground-truth <DIR>\ground_truth.json` and paste digest into `campaign_manifest.json -> ground_truth_sha256`. | **STOP** if digest fails `sha256:<64-hex>` format or GT changes afterwards without re-hashing. |
| **6** | **Stage Private Identity Tokens (`roles.config.json`):** Populate dedicated test account credentials (`user_a`, `user_b`, optional `admin`) with private file ACLs; do **not** put secrets inside manifest/GT/git. | **STOP** if tokens belong to real customers/admins or lack tenant isolation. |
| **7** | **Run Authorization Verification Gate (`0` Requests):** `.\felix.exe validate verify-auth --manifest <DIR>\campaign_manifest.json --ground-truth <DIR>\ground_truth.json --target https://<PILOT_HOST> > <DIR>\preflight\verify_auth_output.txt` | **STOP** on any non-zero exit code (`exit 2`). |
| **8** | **Run 16-Point Offline Pilot Readiness Check (`0` Requests):** `.\felix.exe validate pilot-readiness --manifest <DIR>\campaign_manifest.json --ground-truth <DIR>\ground_truth.json --roles-config <DIR>\roles.config.json --retest-expected <DIR>\retest_expected.json --output-dir <DIR>\initial_run --output <DIR>\preflight\pilot_readiness_check.json --json` | **STOP** unless checks `1..15` pass (`pilot_execution_status == "READY"`). |
| **9** | **Confirm Active UTC Window Immediately Before Launch:** Verify current UTC time sits strictly inside `[window_start, window_end]` with enough buffer for full crawl + verification. | **STOP** if inside final 15 minutes of `window_end`. |
| **10** | **Execute Blind Initial Assessment (`--scope-manifest` Required):** `.\felix.exe assess --target https://<PILOT_HOST> --profile full --scope-manifest <DIR>\campaign_manifest.json --roles-config <DIR>\roles.config.json --rate-limit 5 --output <DIR>\initial_run --verbose` *(Do NOT enable `--allow-state-changing` unless contract explicitly permits isolated synthetic mutation.)* | **ABORT (`Ctrl+C`)** on sustained `5xx` errors, out-of-scope redirect alerts, or unexpected prod PII exposure. |
| **11** | **Inspect Deliverables & Authorization Summary:** Review `<DIR>\initial_run\assessment_report.json`, `.html`, `.sarif`, and `authorization_summary.json`; confirm no excluded routes or private IPs were contacted. | **STOP** and report security defect if any excluded route appears in traffic/findings. |
| **12** | **Coordinate Owner Patching (If Retesting Remediation):** Hand over reproducible PoC evidence (redacted) so the application owner applies a patch in the authorized staging target and notifies ready for retest inside an active UTC window. | **STOP** if UTC window expired — obtain an extended signed `campaign_manifest.json` first. |
| **13** | **Execute Live Retest Verification:** `.\felix.exe assess --retest <DIR>\initial_run\assessment_report.json --target https://<PILOT_HOST> --scope-manifest <DIR>\campaign_manifest.json --roles-config <DIR>\roles.config.json --rate-limit 5 --output <DIR>\retest_run` | **STOP** if `--scope-manifest` validation refuses window/target (`exit 2`). |
| **14** | **Run Strict 9-State Evaluator & Redaction Audit Offline:** `.\felix.exe validate evaluate --ground-truth <DIR>\ground_truth.json --report <DIR>\initial_run\assessment_report.json --authz <DIR>\initial_run\authorization_summary.json --retest <DIR>\retest_run\retest_report.json --retest-expected <DIR>\retest_expected.json --manifest <DIR>\campaign_manifest.json --output <DIR>\evaluation\accuracy_eval.json` | **STOP** if `blind_execution_verified != true` or `redaction_audit.clean != true`. |
| **15** | **Revoke Test Credentials & Archive Clean Report:** Coordinate owner token revocation and secure deletion of `roles.config.json`; publish metrics strictly reporting all 9 states + 95% Wilson CIs honestly. | **Never** delete or downgrade `FN`, `FP`, `INCONCLUSIVE`, or `BLOCKED_BY_AUTH` rows. |

---

## 2. Carried-Forward Phase 9 / 10 Release & CI Blockers

Controlled single-owner pilot onboarding may proceed once Steps 1–8 pass (`checks 1..15 READY`), **provided public software distribution remains paused** until all carried-forward release blockers are resolved:

| Severity | Blocker ID / Area | Current Status | Closure Requirement Before Public Release |
| :---: | :--- | :---: | :--- |
| **P0** | **Windows Authenticode Code Signing (`P12.10`)** | **OPEN** | Sign release Windows executables (`felix.exe`) via Azure Trusted Signing or EV Code Signing certificate and publish checksums + signature verification steps. |
| **P0** | **Production APT Key Provisioning & Historical Key Revocation** | **OPEN** | Provision production `FELIX_APT_SIGNING_KEY` in protected CI secrets, publish formal revocation notice for historical key `8ABF68D0253A139577CA06E7154B088FE357A53D`, and rewrite/scrub commit `f8f2f59d90fb3d02a4664c357e87f7528d3677ab` from public Git history before public mirror/push. |
| **P1** | **CI CGO Race Detector (`go test -race`)** | **OPEN** | Local Windows environment has `CGO_ENABLED=0`; run `CGO_ENABLED=1 go test -race ./...` in Linux/Windows CI with a working C compiler. |
| **P1** | **CI Dependency Vulnerability Scan (`govulncheck`)** | **OPEN** | `govulncheck` is not installed locally; run `govulncheck ./...` cleanly in CI before tag release. |
| **P1** | **External Real-World Accuracy Benchmark** | **OPEN** | Execute authorized external pilot(s) (`n >= 20` controls per priority class across positive & negative controls) and publish full 9-state confusion + Wilson CIs. |
| **P2** | **Clean-Env Verification Script Target** | **OPEN** | Update [scripts/release/test_clean_env.ps1](file:///C:/Jothish/felix/scripts/release/test_clean_env.ps1) (line 65) from `https://example.com` to a loopback fixture. |

---

## 3. Phase 10A Modified Files & Evidence Inventory

### Modified & Added Source Files
- **Validation & Readiness Engine:**
  - [pkg/validation/manifest.go](file:///C:/Jothish/felix/pkg/validation/manifest.go) (`ParseAuthOrCampaignManifest`, `ValidateGroundTruthSHA256Format`)
  - [pkg/validation/readiness.go](file:///C:/Jothish/felix/pkg/validation/readiness.go) (`EvaluatePilotReadiness` — 16 checks, 6 readiness statuses)
  - [pkg/validation/readiness_test.go](file:///C:/Jothish/felix/pkg/validation/readiness_test.go) (`TestPhase10A_PilotReadiness_StatesAndPlaceholders`)
- **CLI Entrypoints & CI Runner Hardening:**
  - [cmd/felix/validate_cmd.go](file:///C:/Jothish/felix/cmd/felix/validate_cmd.go) (`pilot-readiness` / `readiness` CLI subcommand)
  - [cmd/felix/ci_cmd.go](file:///C:/Jothish/felix/cmd/felix/ci_cmd.go), [pkg/ci/types.go](file:///C:/Jothish/felix/pkg/ci/types.go), [pkg/ci/runner.go](file:///C:/Jothish/felix/pkg/ci/runner.go) (`--scope-manifest`, SQLite window binding, `WithDeadline`)
  - [cmd/felix/cve_cmd.go](file:///C:/Jothish/felix/cmd/felix/cve_cmd.go) (`runCVETemplateRun` `--scope-manifest`, `wrapWindowGuard`, `NewSafeTransport`, redirect policy)
  - [cmd/felix/apk_cmd.go](file:///C:/Jothish/felix/cmd/felix/apk_cmd.go) (`--scope-manifest` & pre-intake authorization gate)
  - [cmd/felix/monitor_cmd.go](file:///C:/Jothish/felix/cmd/felix/monitor_cmd.go) (`--scope-manifest` on all `BaseURLs`)
  - [cmd/felix/assessment_cmd.go](file:///C:/Jothish/felix/cmd/felix/assessment_cmd.go) (`runAssessmentBusinessLogic` `IsCurrentlyValid` + `wrapWindowGuard`)
  - [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go), [cmd/felix/direct_cmd.go](file:///C:/Jothish/felix/cmd/felix/direct_cmd.go) (shared `validation.ParseAuthOrCampaignManifest` usage)
  - [cmd/felix/phase10_gate_test.go](file:///C:/Jothish/felix/cmd/felix/phase10_gate_test.go) (`TestPhase10A_AllAdditionalNetworkEntrypoints_RefuseUnauthorizedManifest_ZeroRequests`)

### Rebuilt Binaries & Machine-Readable Proof Artifacts
- [felix.exe](file:///C:/Jothish/felix/felix.exe) and [bin/felix.exe](file:///C:/Jothish/felix/bin/felix.exe) (`32,551,424` bytes, `sha256:d1f6e83e0127d240bc13e4ddcb785a8c8bc475a16870560530de207dc9348bc2`)
- [test/evidence/phase10/pilot_campaigns/TEMPLATE_CAMPAIGN/README.md](file:///C:/Jothish/felix/test/evidence/phase10/pilot_campaigns/TEMPLATE_CAMPAIGN/README.md)
- [test/evidence/phase10/pilot_readiness/pilot_readiness_check.json](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/pilot_readiness_check.json)
- [test/evidence/phase10/pilot_readiness/phase10a_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/phase10a_verification_summary.json)
- [test/evidence/phase10/pilot_readiness/authorization_refusal_proof.json](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/authorization_refusal_proof.json)
- [test/evidence/phase10/pilot_readiness/ground_truth_integrity_proof.json](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/ground_truth_integrity_proof.json)
- [test/evidence/phase10/pilot_readiness/command_enforcement_matrix.json](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/command_enforcement_matrix.json)
- [test/evidence/phase10/pilot_readiness/full_go_test_output.txt](file:///C:/Jothish/felix/test/evidence/phase10/pilot_readiness/full_go_test_output.txt)

### Consolidated Reports
- **Phase 10A Reports ([docs/engineering/phase10a/](file:///C:/Jothish/felix/docs/engineering/phase10a/)):**
  - [PHASE_10A_PILOT_ONBOARDING_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase10a/PHASE_10A_PILOT_ONBOARDING_REPORT.md)
  - [PHASE_10A_AUTHORIZATION_AND_READINESS_AUDIT.md](file:///C:/Jothish/felix/docs/engineering/phase10a/PHASE_10A_AUTHORIZATION_AND_READINESS_AUDIT.md)
  - [PHASE_10A_EXECUTION_RUNBOOK_AND_HANDOVER.md](file:///C:/Jothish/felix/docs/engineering/phase10a/PHASE_10A_EXECUTION_RUNBOOK_AND_HANDOVER.md)
- **Additional Phase 10A Onboarding Templates ([test/evidence/phase8/realworld_readiness/](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/)):**
  - [roles_config_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/roles_config_template.json)
  - [pilot_operator_checklist_template.md](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/pilot_operator_checklist_template.md)
- **Preserved Phase 10 Baseline Reports ([docs/engineering/phase10/](file:///C:/Jothish/felix/docs/engineering/phase10/)):**
  - [PHASE_10_FINAL_TECHNICAL_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_FINAL_TECHNICAL_REPORT.md)
  - [PHASE_10_REAL_WORLD_ACCURACY_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_REAL_WORLD_ACCURACY_REPORT.md)
  - [PHASE_10_REMEDIATION_AND_RELEASE_HANDOVER.md](file:///C:/Jothish/felix/docs/engineering/phase10/PHASE_10_REMEDIATION_AND_RELEASE_HANDOVER.md)
