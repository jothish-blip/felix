# FELIX PHASE 10 — REAL-WORLD ACCURACY REPORT

**Project:** FELIX — Security Assessment & Vulnerability Intelligence Platform  
**Repository:** `C:\Jothish\felix`  
**Phase 10 Pilot Classification:** **`A. PILOT NOT EXECUTED — PREREQUISITES MISSING`**  
**Date:** 2026-11-12

> [!IMPORTANT]
> **Real-World External Accuracy Is `NOT EXECUTED`:**  
> Zero owner-authorized external deployed applications were scanned during Phase 10 (`0` external requests sent). External real-world detection accuracy (Precision, Recall, Specificity, 95% Wilson CIs, and remediation retest accuracy on a live deployed target) remains **unmeasured** until an owner-authorized pilot engagement is executed with an independently constructed, pre-locked `GroundTruthRegistry`. Local lab results from Phase 7 and synthetic ephemeral tests from Phase 8 are reproduced separately in Section 2 strictly as pre-pilot baselines and must **not** be presented as external real-world accuracy.

---

## 1. Phase 10 External Pilot Accounting Scorecard

| Pilot Requirement / Metric | Phase 10 Observed Status | Count / Value | 95% Wilson CI | Notes / Blocking Gap |
| :--- | :---: | :---: | :---: | :--- |
| **Owner-Signed Authorization Contract** | **MISSING** | `0` (`confirmed: false` template only) | — | Only [authorization_contract_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/authorization_contract_template.json) exists |
| **Pre-Locked Independent External Ground Truth** | **MISSING** | `0` external entries | — | Only [ground_truth_registry_template.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ground_truth_registry_template.json) exists |
| **Owner-Provided Target URL & Multi-Role Credentials** | **MISSING** | `0` external environments | — | Zero live external target URLs or test accounts present |
| **Blind Pilot Execution (`executed_at`)** | **NOT EXECUTED** | `0` external requests sent | — | Refused cleanly by CLI gate ([phase10_gate_refusal_proof.json](file:///C:/Jothish/felix/test/evidence/phase10/audit/phase10_gate_refusal_proof.json)) |
| **True Positives (`TP`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **False Positives (`FP`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **False Negatives (`FN`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **True Negatives (`TN`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **Inconclusive (`INCONCLUSIVE`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **Not Tested (`NOT_TESTED`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **Not Configured (`NOT_CONFIGURED`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **Safety Excluded (`SAFETY_EXCLUDED`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **Out of Scope (`OUT_OF_SCOPE`)** | `NOT EXECUTED` | `0` | `N/A` | Requires external pilot run |
| **External Precision (`TP / (TP + FP)`)** | `NOT EXECUTED` | `N/A` | `N/A` | Denominator `0` |
| **External Recall (`TP / (TP + FN)`)** | `NOT EXECUTED` | `N/A` | `N/A` | Denominator `0` |
| **External Specificity (`TN / (TN + FP)`)** | `NOT EXECUTED` | `N/A` | `N/A` | Denominator `0` |
| **External Execution Coverage** | `NOT EXECUTED` | `N/A` | `N/A` | Denominator `0` |
| **External Remediation Retest Accuracy** | `NOT EXECUTED` | `0` findings retested | `N/A` | Requires patched external pilot retest |

---

## 2. Prior Pre-Pilot Baselines (For Reference Only — Not External Pilot Evidence)

The following measurements remain unchanged from Phases 7 and 8 and verify **harness engineering and local controlled lab behavior**, not generalization to external deployed applications:

1. **Phase 8 Ephemeral CLI Blind Harness ([PHASE_8_ACCURACY_VALIDATION_REPORT.md](file:///C:/Jothish/felix/docs/engineering/phase8/PHASE_8_ACCURACY_VALIDATION_REPORT.md), [ephemeral_harness_accuracy_eval.json](file:///C:/Jothish/felix/test/evidence/phase8/realworld_readiness/ephemeral_harness_accuracy_eval.json)):**
   - Population: `Phase8EphemeralCLIApp` (`N=4` GT entries, evaluated in-scope population `= 3`, excluded `/admin/reset` `OOS=1`).
   - Confusion Counts: `TP=2`, `FP=0`, `FN=0`, `TN=1`, `Inconclusive=0`, `NotTested=0`, `NotConfigured=0`, `SafetyExcluded=0`, `OutOfScope=1`.
   - Precision: `100.00%` (`2/2`, 95% Wilson CI `[34.24%, 100.00%]`).
   - Recall: `100.00%` (`2/2`, 95% Wilson CI `[34.24%, 100.00%]`).
   - Specificity: `100.00%` (`1/1`, 95% Wilson CI `[20.65%, 100.00%]`).
   - Execution Coverage: `100.00%` (`3/3`, 95% Wilson CI `[43.85%, 100.00%]`).
   - Multi-Role Retest Accuracy: `100.00%` (`3/3` on patched mock: `correct_fixed=2`, `correct_still_present=1`, `incorrect=0`, CI `[43.85%, 100.00%]`).
   - Statistical Caveat: Wide Wilson confidence intervals (`[20.65%, 100%]` at `n=1`) show synthetic harness `n=3` cannot substantiate real-world accuracy rates.
2. **Phase 7 Controlled Local OWASP Labs (`17` runs across OWASP VAmPI, OWASP Juice Shop `v20.2.0`, and OWASP crAPI `v1.1.5`):**
   - CMDI false positives eliminated (`96 -> 0` across `17` runs).
   - Summary/JSON/SARIF parity (`100%`, `v4: 7/7`, `j4: 7/7`, `c4: 5/5`) and cleartext credential redaction verified.
   - Open accuracy constraints carried forward: crAPI relative microservice JS path resolution (`21` inconclusive checks in `c4`), conservative `DETECTED` (`POTENTIAL`) retention on public GET routes in Juice Shop (`j4`), root-level header checking, OAST/headless browser dependency for out-of-band/DOM classes, and manual verification requirement for mutating-method BOLA remediation retests.

---

## 3. What FELIX Can and Cannot Claim After Phase 10

### Verified Capabilities (Offline / Local Harness)
- Fail-closed authorization enforcement (`--scope-manifest` and `felix validate verify-auth`) across `assess`, `validate`, `scan`, `recon`, `secrets`, and direct module commands (`web`, `api`, `auth`, `authz`, `bola`, `bfla`, `bopla`, `cloud`) — verified `0` outbound requests on refusal.
- Cryptographically hash-locked pre-scan ground-truth verification (`ground_truth_sha256` format check and `CanonicalGroundTruthSHA256` comparison via `felix validate verify-auth --ground-truth`).
- End-to-end 9-state evaluator, blind integrity validation, Wilson 95% CI calculation, redaction audit, and full `49/49` package Go test pass under `CGO_ENABLED=0`.

### Explicitly Unproven After Phase 10
- **Live external attack-surface discovery rate** on a real internet/intranet deployed architecture (CDN/WAF, reverse-proxy prefixes, SPA auth flows, non-standard API gateways).
- **External vulnerability detection precision, recall, specificity, and negative-control discrimination** (`n >= 20` independent ground-truth controls per vulnerability class).
- **External multi-role authorization accuracy** under real session/CSRF/IdP token issuance and live owner-applied patch retesting.
