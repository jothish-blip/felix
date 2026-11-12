# FELIX PHASE 8 — FINAL TECHNICAL REPORT

**Project:** FELIX — Security Assessment & Vulnerability Intelligence Platform  
**Repository:** `C:\Jothish\felix` (`main`, baseline `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9`)  
**Environment:** Windows 11, Go `go1.27.0 windows/amd64`  
**Phase Status:** **READINESS FRAMEWORK COMPLETE & VERIFIED (EXTERNAL SCANNING HELD AT AUTHORIZATION GATE)**  
**Completion Date:** 2026-11-12  

---

## 1. Executive Summary

Phase 8 established FELIX's repeatable, cryptographically tamper-evident real-world accuracy validation framework and closed three verification/retest defects uncovered during blind end-to-end harness execution.

No external or third-party deployed web application was scanned during this phase because no external owner-signed authorization contract and pre-locked independent ground-truth registry existed in this environment. In accordance with Phase 8 policy, external execution stops at the fail-closed authorization gate until those prerequisites are supplied. No claim of universal accuracy or live real-world accuracy is made.

---

## 2. Engineering Deliverables Built in Phase 8

### 2.1 Independent Validation & Accuracy Package (`pkg/validation`)

| File | Key Types & Functions | Purpose |
| :--- | :--- | :--- |
| [types.go](file:///C:/Jothish/felix/pkg/validation/types.go) | `GroundTruthStatus`, 9 `OutcomeClassification` states, `AuthorizationContract`, `CampaignManifest`, `GroundTruthRegistry`, `ConfusionCounts`, `WilsonInterval`, `MetricRate`, `ClassMetrics`, `RetestExpectedItem`, `RetestAccuracyMetrics`, `AccuracyEvaluationReport` | Machine-readable schema separating ground truth, manifest metadata, 9 confusion/coverage states, retest verification, redaction auditing, and `universal_accuracy_claimed: false`. |
| [manifest.go](file:///C:/Jothish/felix/pkg/validation/manifest.go) | `CanonicalGroundTruthSHA256`, `ComputeFileSHA256`, `BuildScopeValidator`, `ValidateAuthorizationGate`, `VerifyCampaignBlindness`, `AuditReportRedaction` | Locks independent ground truth with canonical SHA-256 prior to scanning, enforces contract confirmation/scope/exclusions/UTC window, verifies `derived_from_scanner == false` and timestamp precedence, and scans outputs for unredacted secrets (`secrets.RedactText` / `secrets.Detector.ScanContent`). |
| [evaluator.go](file:///C:/Jothish/felix/pkg/validation/evaluator.go) | `CanonicalVulnClass`, `ComputeWilson95`, `ComputeRate`, `ComputeF1`, `EvaluateAccuracy` | Enforces verified-only `TP` promotion, prevents `POTENTIAL` candidates from counting as `TP` and `INCONCLUSIVE` checks from counting as `TN`, evaluates negative controls and `retest_report.json` against `RetestExpectedItem`, computes 95% Wilson CIs, and guards invalid zero denominators. |
| [evaluator_test.go](file:///C:/Jothish/felix/pkg/validation/evaluator_test.go) | `TestPhase8_AuthorizationGate_WindowAndExclusions`, `TestPhase8_EvaluateAccuracy_StrictNineStates_And_NoInconclusiveAsTN`, `TestPhase8_DenominatorZero_TamperedGT_And_SecretLeakDetection` | Unit-level verification of window/scope enforcement, 9-state accounting invariants, zero-denominator suppression, tampered registry rejection, and secret leak detection. |

### 2.2 Authorization Gate, Exclusion Propagation & `felix validate` CLI

| File | Changes Implemented |
| :--- | :--- |
| [validate_cmd.go](file:///C:/Jothish/felix/cmd/felix/validate_cmd.go) | Implemented `felix validate` subcommands: `hash-gt` (canonical ground-truth SHA-256), `verify-auth` (pre-flight authorization, target, exclusion, and UTC window check), and `evaluate` (blind report + authz summary + retest verdict evaluation outputting `AccuracyEvaluationReport` JSON). |
| [main.go](file:///C:/Jothish/felix/cmd/felix/main.go) | Registered `validate` in CLI command dispatch and help text. |
| [assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go) | Added `--exclude-paths`, `--exclude-urls`, `--scope-manifest`, and `buildAssessScopePolicy`; enforced `ValidateAuthorizationGate` prior to transmitting any HTTP traffic (exit code `2`, `0` requests on refusal); propagated excluded paths/URLs (`ScopeExcluded`) into `crawler` and `webvuln`; updated `runRetest` to enforce `--scope-manifest`/exclusions and load `--roles-config` mapped by `accessor_alias` (`USER_A`/`USER_B`/`ADMIN`). |
| [validate_phase8_test.go](file:///C:/Jothish/felix/cmd/felix/validate_phase8_test.go) | Added CLI integration tests `TestPhase8_AuthorizationGate_RefusesExpiredWindowAndOutOfScope_ZeroRequests`, `TestPhase8_ExcludedPathsNeverTouchedDuringAssessAndRetest`, and `TestPhase8_BlindValidationReadiness_EndToEndHarness`. |

---

## 3. Real Defects Uncovered & Fixed During Phase 8 Validation

End-to-end execution of the blind ephemeral harness uncovered three concrete defects in `--retest` and corroborating finding attribution, all of which were repaired and regression-tested:

1. **Single-Identity & Unmatched Token Replay in `--retest` ([assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go)):**
   - *Symptom:* `runRetest` previously ignored `--roles-config`, preventing multi-identity BOLA findings from supplying secondary test tokens during remediation retesting (`accessor_alias`).
   - *Fix:* `runRetest` now honors `--roles-config` and `--scope-manifest`, matching finding `details["accessor_alias"]` (`USER_A`, `USER_B`, `ADMIN`) to inject the corresponding credential for bounded read verification.
2. **Unexpanded Path Placeholders & False `FIX DETECTED` on HTTP 404 in `proveBOLA` ([prover.go](file:///C:/Jothish/felix/pkg/investigation/prover.go)):**
   - *Symptom:* Retesting BOLA endpoints such as `/api/items/%7Bitem_id%7D` sent literal `%7Bitem_id%7D` instead of `details["object_id"]` (`item-alice-1`, `item-bob-1`), received HTTP `404 Not Found`, and could falsely treat `404` or unresolved placeholders as remediation.
   - *Fix:* Added `expandPlaceholderWithObjectID` in `proveBOLA` to substitute concrete `object_id` parameters safely; changed HTTP `404 Not Found` and unresolved template routes in BOLA retests to fail closed to `StatusNotTested` (`RETEST INCONCLUSIVE`). Live reproduction against an unpatched server now yields `[VULNERABILITY STILL PRESENT]`, while patching cross-user access to HTTP `403` yields `FIX DETECTED`.
3. **Corroborating Finding Over-Counting in Accuracy Evaluator ([evaluator.go](file:///C:/Jothish/felix/pkg/validation/evaluator.go)):**
   - *Symptom:* When multiple verified BOLA objects (`/api/items/{item_id}` on `item-alice-1` and `item-bob-1`) matched a single pattern-level ground-truth entry, additional verified instances were counted as `FP`.
   - *Fix:* Updated `EvaluateAccuracy` to attribute additional verified findings corroborating an already-satisfied `VULNERABLE` ground-truth entry without inflating `TP` denominators or introducing false `FP`s.

---

## 4. Machine-Readable Evidence Artifacts & Build/Test Verification

All readiness templates and verified ephemeral harness outputs reside under [test/evidence/phase8/realworld_readiness/](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness) (preserving historical `8.1_*`, `8.2_*`, and `8.3_*` files intact):

- Templates: [authorization_contract_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/authorization_contract_template.json), [ground_truth_registry_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ground_truth_registry_template.json) (`sha256:6ee7cc535dd6a87355d3952643f3472269f012dd7644f657b5d7304a6e2297b0`), [campaign_manifest_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/campaign_manifest_template.json), [retest_expected_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/retest_expected_template.json)
- CLI Harness Artifacts: [ephemeral_ground_truth.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_ground_truth.json) (`sha256:a70329e9bfebbcf4942c5a191fecc178db7b3daedf78c293c2fd9cb0e07201a8`), [ephemeral_campaign_manifest.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_campaign_manifest.json), [ephemeral_harness_accuracy_eval.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_harness_accuracy_eval.json)

### Post-Edit Repository Verification

| Check Command | Observed Result | Scope |
| :--- | :--- | :--- |
| `go build ./...` | **PASS (exit 0)** | Entire workspace, plus rebuilt [felix.exe](file:///C:/Jothish/felix/felix.exe) & [bin/felix.exe](file:///C:/Jothish/felix/bin/felix.exe) |
| `go vet ./...` | **PASS (exit 0)** | Entire workspace |
| `go test -p 1 -count=1 ./...` | **PASS (exit 0)** | **49/49 tested packages `ok`** (including `felix/pkg/validation`, `felix/pkg/investigation`, `felix/cmd/felix`, `felix/test`, `felix/test/lab`), `0` failures; `2` helper packages reported `[no test files]` (`felix/scratch`, `felix/test/lab/cmd/multiclass`) |
| External Target Testing | **STOPPED AT AUTH GATE (0 external requests)** | No external owner authorization contract or external ground-truth registry provided in this environment |
