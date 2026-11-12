# FELIX PHASE 8 — REMEDIATION & REAL-WORLD EXECUTION HANDOVER

**Repository:** `C:\Jothish\felix`  
**Decision Status:** **READY FOR CONTROLLED REAL-WORLD PILOT / EXTERNAL EXECUTION BLOCKED ON PREREQUISITES**  
**Date:** 2026-11-12  

---

## 1. Executive Handover Decision

FELIX's validation engineering, authorization gate, scope exclusion controls, multi-role `--retest` engine, and 9-state statistical evaluation pipeline (`felix validate`) are complete and verified (`49/49` Go packages passing, `0` failures).

**External live testing is intentionally held at the authorization gate (`Stop` triggered cleanly with `0` external requests sent)** because the current workspace does not contain:
1. A written, confirmed owner authorization contract (`confirmed: true`, signed reference ID, target origin allowlist, excluded paths, and active UTC testing window), and
2. An independently established, pre-locked ground-truth registry (`derived_from_scanner: false`) for an authorized deployed target.

---

## 2. Step-by-Step Real-World Pilot Execution Runbook

Operators executing the next external validation campaign must complete steps 1–6 strictly in order:

### Step 1: Establish & Lock Independent Ground Truth (Before Any FELIX Scan)
Copy [ground_truth_registry_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ground_truth_registry_template.json), populate `VULNERABLE`, `SECURE_NEGATIVE_CONTROL`, and `EXCLUDED_SCOPE` entries from application source code, API schemas, and manual verification (`derived_from_scanner: false`), then lock its SHA-256 digest:
```powershell
.\felix.exe validate hash-gt --ground-truth <path\ground_truth.json>
```

### Step 2: Obtain Owner Sign-Off & Populate Campaign Manifest
Copy [campaign_manifest_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/campaign_manifest_template.json) (and optionally [authorization_contract_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/authorization_contract_template.json)), insert the owner-confirmed targets, `excluded_paths`, `excluded_urls`, active UTC `window_start`/`window_end`, `"confirmed": true`, and the SHA-256 digest from Step 1. Verify before running:
```powershell
.\felix.exe validate verify-auth --manifest <path\campaign_manifest.json> --target <target_url>
```
*(FELIX exits non-zero with `0` HTTP requests sent if `confirmed != true`, the UTC window is inactive, or the target matches an exclusion / sits outside `authorized_targets`.)*

### Step 3: Execute Blind Assessment
Supply only the target URL, manifest, exclusions, and test identity credentials (`roles.json` without modifying ground truth):
```powershell
.\felix.exe assess --target <target_url> --profile full --roles-config <path\roles.json> --scope-manifest <path\campaign_manifest.json> --exclude-paths "/admin/reset,/billing/charge" --output <path\blind_run>
```

### Step 4: Execute Post-Patch Multi-Role Retest
After the application owner remediates selected findings, populate [retest_expected_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/retest_expected_template.json) and execute `--retest` within an active authorized window:
```powershell
.\felix.exe assess --target <target_url> --retest <path\blind_run\assessment_report.json> --roles-config <path\roles.json> --scope-manifest <path\campaign_manifest.json> --output <path\retest_run>
```

### Step 5: Compute Blind 9-State Accuracy & Wilson Confidence Intervals
```powershell
.\felix.exe validate evaluate --ground-truth <path\ground_truth.json> --report <path\blind_run\assessment_report.json> --authz <path\blind_run\authorization_summary.json> --retest <path\retest_run\retest_report.json> --retest-expected <path\retest_expected.json> --manifest <path\campaign_manifest.json> --output <path\accuracy_eval.json>
```

### Step 6: Review Quality & Integrity Gates Before Reporting
Confirm in `accuracy_eval.json`:
- `manifest_integrity_ok == true` and `blind_execution_verified == true`
- `redaction_audit.clean == true` and `report_summary_consistent == true`
- `universal_accuracy_claimed == false`
- Report per-class denominators, valid/invalid metric flags, 95% Wilson CIs, `execution_coverage` alongside `recall`, and separate `candidate_only_matches` / `inconclusive` counts from `TN` and `TP`.

---

## 3. Known Technical Limitations & Recommended Future Improvements

These existing architectural boundaries should be tracked prior to broader production rollouts:

| Area | Current Behavior / Constraint | Operational Impact / Mitigation |
| :--- | :--- | :--- |
| **crAPI Microservice Prefix Stitching** | JS bundle extractors can leave relative microservice routes unprefixed (`/workshop`, `/community`) across dynamic helpers (observed `21` inconclusive checks in Phase 7 `c4`). | Document known API gateway base prefixes cleanly in OpenAPI specs on pilot targets, or extend JS client prefix resolution in future work. |
| **Public GET BFLA Candidate Noise** | Unauthenticated/public GET routes (`/api/Products`, `/rest/captcha` in Juice Shop `j4`) can surface at `MEDIUM / DETECTED` (`POTENTIAL`) rather than auto-suppressed. | Evaluator keeps `POTENTIAL` candidates out of `VERIFIED TP` (`candidate_only_matches` / `candidate_fps`), preserving `VERIFIED` precision. |
| **External OAST & Headless DOM XSS** | Out-of-band SSRF/blind XXE/blind CMDI require reachable OAST callback infrastructure (`NOT_CONFIGURED` unless provisioned); pure client-side DOM XSS sinks depend on browser/DOM instrumentation availability. | Mark target ground-truth entries requiring unprovisioned infrastructure with `requires_config: "OAST"` or `"BROWSER_DOM"` so `EvaluateAccuracy` accounts for them honestly as `NOT_CONFIGURED`. |
| **Per-Route Security Headers** | Security header checks inspect the root target response (`f.Target` / `/ui/`) rather than per-endpoint overrides. | Document root vs. sub-path expectations clearly when building `GroundTruthRegistry` header controls. |
| **State-Changing Mutating Retests** | By design, `proveBOLA` skips mutating methods (`POST`/`PUT`/`DELETE`) during `--retest` and fails closed to `RETEST INCONCLUSIVE`. | Manual verification remains required for mutating authorization fixes to protect deployed target data integrity. |

---

## 4. Phase 8 File Inventory

- Implementation: [pkg/validation/types.go](file:///C:/Jothish/felix/pkg/validation/types.go), [pkg/validation/manifest.go](file:///C:/Jothish/felix/pkg/validation/manifest.go), [pkg/validation/evaluator.go](file:///C:/Jothish/felix/pkg/validation/evaluator.go), [cmd/felix/validate_cmd.go](file:///C:/Jothish/felix/cmd/felix/validate_cmd.go), [cmd/felix/main.go](file:///C:/Jothish/felix/cmd/felix/main.go), [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go), [pkg/investigation/prover.go](file:///C:/Jothish/felix/pkg/investigation/prover.go)
- Tests: [pkg/validation/evaluator_test.go](file:///C:/Jothish/felix/pkg/validation/evaluator_test.go), [cmd/felix/validate_phase8_test.go](file:///C:/Jothish/felix/cmd/felix/validate_phase8_test.go)
- Machine-Readable Readiness Artifacts: [test/evidence/phase8/realworld_readiness/](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness)
- Consolidated Phase 8 Reports (`docs/engineering/phase8/`): [PHASE_8_FINAL_TECHNICAL_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase8/PHASE_8_FINAL_TECHNICAL_REPORT.md), [PHASE_8_ACCURACY_VALIDATION_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase8/PHASE_8_ACCURACY_VALIDATION_REPORT.md), [PHASE_8_REMEDIATION_HANDOVER.md](file:///C:/Jothish/felix/docs/engineering/phase8/PHASE_8_REMEDIATION_HANDOVER.md)
