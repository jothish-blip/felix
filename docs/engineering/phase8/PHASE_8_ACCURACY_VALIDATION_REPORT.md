# FELIX PHASE 8 — ACCURACY VALIDATION REPORT

**Repository:** `C:\Jothish\felix`  
**Validation Scope:** Phase 8 Ephemeral CLI Blind Harness + Phase 7 Controlled Local Lab Baseline  
**Date:** 2026-11-12  

> [!IMPORTANT]
> **Scope & Accuracy Disclaimer:** No external production or third-party deployed application was assessed during Phase 8 because neither an owner-signed authorization contract nor an external independent ground-truth inventory was available. All empirical figures reported below strictly reflect the evaluated controlled populations and carry zero claim of universal detection accuracy or live real-world accuracy.

---

## 1. Validation Methodology & 9-State Accounting Standard

Implemented in [pkg/validation/evaluator.go](file:///C:/Jothish/felix/pkg/validation/evaluator.go) and exposed via `felix validate`:

1. **Independent Pre-Locked Ground Truth (`derived_from_scanner: false`):** Ground truth must be derived from source specifications, API definitions, or manual review and SHA-256 locked (`felix validate hash-gt`) *before* FELIX executes.
2. **Blind Execution (`blind_execution: true`):** Scanners receive only target URL, `--roles-config`, `--scope-manifest`, and general `--profile` settings — never ground-truth hints. `VerifyCampaignBlindness` validates registry digest equality, non-scanner derivation, and timestamp ordering (`GroundTruthRegisteredAt <= ExecutedAt`).
3. **Mutually Exclusive 9-State Outcomes:**
   - `TP`: Verified finding (`VERIFIED` tier, never `POTENTIAL` candidates) matching an executable in-scope `VULNERABLE` entry with evidence.
   - `FP`: Finding falsely reported against a negative control or unmapped in-scope surface (`candidate_fps` vs `verified_fps` tracked separately).
   - `FN`: Executable in-scope `VULNERABLE` entry missed or left only as unverified `POTENTIAL` (`candidate_only_matches` counted separately).
   - `TN`: Explicitly verified `SECURE_NEGATIVE_CONTROL` endpoint confirmed not vulnerable without false alerts.
   - `INCONCLUSIVE`: Bounded check completed with ambiguous result — **never counted as `TN`**.
   - `NOT_TESTED`: Valid target path not exercised by the run.
   - `NOT_CONFIGURED`: Entry blocked by missing prerequisite configuration (e.g., `MULTI_ROLE`, `OAST`, `BROWSER_DOM`).
   - `SAFETY_EXCLUDED`: Intentionally omitted by destructive safety policies (`/createdb`, state-changing guardrails).
   - `OUT_OF_SCOPE`: Explicitly excluded via authorization contract / `--exclude-paths` / `--exclude-urls`.
4. **Statistical Discipline & Separation of Coverage vs. Recall:**
   - `Precision = TP / (TP + FP)` (suppressed as `valid: false` if `TP + FP == 0`).
   - `Recall = TP / (TP + FN)` (only across executable in-scope positives; suppressed if `TP + FN == 0`).
   - `Specificity = TN / (TN + FP)` (suppressed if `TN + FP == 0`).
   - `Execution Coverage` reported independently from `Recall`.
   - Binomial metrics compute **95% Wilson score confidence intervals** (`ComputeWilson95`).

---

## 2. Empirical Results: Phase 8 Ephemeral CLI Blind Harness

Artifact: [ephemeral_harness_accuracy_eval.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_harness_accuracy_eval.json)  
Campaign Manifest: [ephemeral_campaign_manifest.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_campaign_manifest.json)  
Ground Truth Registry: [ephemeral_ground_truth.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_ground_truth.json) (`sha256:a70329e9bfebbcf4942c5a191fecc178db7b3daedf78c293c2fd9cb0e07201a8`)

### 2.1 Overall & Integrity Metrics (`Phase8EphemeralCLIApp`, N=4 GT Entries, Evaluated Pop=3)

| Dimension / Metric | Observed Value | Numerator / Denominator | 95% Wilson CI | Status / Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Blind Integrity & Manifest Hash** | `true` / `true` | — | — | `derived_from_scanner=false`, hash verified |
| **Redaction Audit** | Clean (`leaks: []`) | `4` findings inspected | — | `0` bearer tokens/secrets leaked |
| **Summary vs. Findings Parity** | `true` (`4 == 4`) | `summary_total == len(findings)` | — | Zero count drift |
| **Scope Exclusion Compliance** | `0` hits | `/admin/reset` excluded (`OOS=1`) | — | Confirmed at HTTP handler & evaluator |
| **Confusion Counts** | `TP=2, FP=0, FN=0, TN=1` | `OOS=1`, `Inconclusive=0`, `NotTested=0`, `NotCfg=0`, `SafetyExcl=0` | — | Additional corroborating BOLA finding attributed cleanly without inflating FP |
| **Precision** | **100.00%** | `2 / 2` | `[34.24%, 100.00%]` | Verified findings only |
| **Recall** | **100.00%** | `2 / 2` | `[34.24%, 100.00%]` | Executable positive population |
| **Specificity** | **100.00%** | `1 / 1` | `[20.65%, 100.00%]` | `X-Content-Type-Options: nosniff` control |
| **Execution Coverage** | **100.00%** | `3 / 3` | `[43.85%, 100.00%]` | All 3 in-scope GT items executed |
| **Multi-Role Retest Accuracy** | **100.00%** | `3 / 3` (`correct_fixed=2`, `correct_still_present=1`, `incorrect=0`) | `[43.85%, 100.00%]` | BOLA items patched to HTTP `403` detected `FIXED`; unpatched CSP detected `STILL_PRESENT` |

*(Unpatched retest baseline was additionally verified in `TestPhase8_BlindValidationReadiness_EndToEndHarness` in [validate_phase8_test.go](file:///C:/Jothish/felix/cmd/felix/validate_phase8_test.go), yielding `fixed_count=0`, `still_present_count=3`, `inconclusive_count=1` on `RECON-INFO`, and `TP=2, FP=0, FN=0, TN=1, OOS=1`.)*

### 2.2 Vulnerability-Class Breakdown (`ephemeral_harness_accuracy_eval.json`)

| Vulnerability Class | Evaluated Pop | TP | FP | FN | TN | Out of Scope | Precision | Recall | Specificity | Execution Coverage |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`BOLA`** | `1` | `1` | `0` | `0` | `0` | `0` | `100.00%` (`1/1`) | `100.00%` (`1/1`) | `N/A (TN+FP == 0)` | `100.00%` (`1/1`, CI `[20.65%, 100%]`) |
| **`SECURITY_HEADERS`** | `2` | `1` | `0` | `0` | `1` | `0` | `100.00%` (`1/1`) | `100.00%` (`1/1`) | `100.00%` (`1/1`) | `100.00%` (`2/2`, CI `[34.24%, 100%]`) |
| **`BFLA` (`/admin/reset`)** | `0` | `0` | `0` | `0` | `0` | `1` | `N/A (TP+FP == 0)` | `N/A (TP+FN == 0)` | `N/A (TN+FP == 0)` | `N/A (executable == 0)` |

---

## 3. Baseline Local Lab Validation Evidence (Phase 7 Record)

As recorded in [FELIX_PHASE_7_ACCURACY_METRICS.md](file:///C:/Jothish/felix/docs/engineering/phase7/FELIX_PHASE_7_ACCURACY_METRICS.md), [FELIX_PHASE_7_EVIDENCE_INTEGRITY_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase7/FELIX_PHASE_7_EVIDENCE_INTEGRITY_REPORT.md), and [FELIX_PHASE_7_VULNERABILITY_CLASS_AUDIT.md](file:///C:/Jothish/felix/docs/engineering/phase7/FELIX_PHASE_7_VULNERABILITY_CLASS_AUDIT.md) across `17` controlled lab runs on **OWASP VAmPI**, **OWASP Juice Shop `v20.2.0`**, and **OWASP crAPI `v1.1.5`**:

| Validation Dimension | Recorded Local Lab Performance & Remaining Scope Boundaries |
| :--- | :--- |
| **Discovery Coverage** | VAmPI `v4`: `13` endpoints (`17` on `/ui/` `v6`); Juice Shop `j4`: `48` unique JS/REST candidates (`66` attack surface); crAPI `c4`: `31` JS bundle candidates (`33` surface), though crAPI microservice prefix splitting yielded `21` inconclusive object checks. |
| **Verification vs. FP Suppression** | CMDI FPs reduced `96 -> 0` across all `17` runs (`-100%`). VAmPI `v4` verified `BOLA`, `BFLA`, and `BOPLA` (`6 VERIFIED`, `1 NOT_VERIFIED` recon). Juice Shop `j4` kept `5` GET BFLA candidates (`/api/Addresss`, `/api/Cards`, `/api/Products`, `/api/Users`, `/rest/captcha`) conservatively at `DETECTED` (`POTENTIAL`) rather than over-promoting `/api/Products` or `/rest/captcha` to `VERIFIED`. |
| **Evidence, Redaction & Parity** | `100%` (`17/17`) summary parity (`summary.total_findings == len(findings)`), JSON/SARIF parity (`v4: 7/7`, `j4: 7/7`, `c4: 5/5`), `0` false zero-finding banners, and `0` cleartext secrets leaked on crAPI `/.env`. |
| **Safety & Retest Reliability** | `--safe` runs (`v5`, `j5`, `c5`) executed `0` active authz/CMDI probes. Destructive DB reset exclusions logged across VAmPI/Juice Shop/crAPI. Note: Phase 7 `v7` cross-user BOLA retest failed closed (`inconclusive`) before Phase 8 added `--roles-config` + `accessor_alias` + `object_id` path expansion; Phase 8 resolved that gap and re-verified live multi-role `--retest` in `cmd/felix`. |

---

## 4. Assessment Readiness Conclusions

- **Engineering & Evaluation Methodology:** Verified operational across `49/49` passing Go packages (`0` failures) and CLI end-to-end execution.
- **Sample-Size Caution:** Wide 95% Wilson CIs (`[34.24%, 100%]` at `n=2`, `[20.65%, 100%]` at `n=1`) demonstrate why statistically meaningful real-world precision/recall requires executing the Phase 8 runbook against a larger owner-authorized deployed application with `n >= 20` independent ground-truth controls per vulnerability class.
