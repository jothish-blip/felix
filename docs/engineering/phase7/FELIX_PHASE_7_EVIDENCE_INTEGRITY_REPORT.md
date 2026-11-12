# FELIX PHASE 7 — EVIDENCE INTEGRITY, DEDUPLICATION & CROSS-FORMAT CONSISTENCY REPORT

**Repository:** `C:\Jothish\felix`  
**Completion Date:** 2026-11-12  

---

## 1. Executive Summary

During Phase 6, report outputs contained severe structural and evidence contradictions:
1. **`summary.total_findings != len(findings)`** (VAmPI `v4`: `3 != 4`; crAPI `c4`: `12 != 13`).
2. **Stale Commercial Report Contradiction:** `BuildCommercialReport` (`pkg/report/commercial_builder.go`) saw `0` recognized findings and printed `"No security findings were identified within the evaluated scope"` inside JSON reports containing `CRITICAL` findings.
3. **100% `"NOT TESTED"` Status Drift:** `pkg/investigation/live_session.go` wrote `"CONFIRMED"` / `"POTENTIAL"` strings that `pkg/report/normalize.go` did not recognize, coercing verified findings to `"OBSERVED"` or `"NOT TESTED"`.
4. **Silent Header Collisions:** `pkg/correlation/fingerprint.go` merged distinct security headers (`HDR-CSP`, `HDR-XFO`, `HDR-NOSNIFF`) under a single `"Missing Security Header"` discriminator while retaining stale summary counts.
5. **Truncated `safe_curl_command`:** `pkg/investigation/prover.go` passed `f.Target` instead of concrete `f.Endpoint` to `FormatSafeCurl(...)`.
6. **Clean Secret Redaction Audit:** All response snippets and `/.env` exposures must strictly redact credentials/tokens before persisting JSON/HTML/SARIF outputs.

Phase 7 eliminated all six integrity defects across JSON, SARIF, HTML, Commercial Report, and Retest JSON outputs.

---

## 2. Remediations Implemented

| Defect | Package / File | Remediation | Verification Test |
| :--- | :--- | :--- | :--- |
| **PH7-D07** | `pkg/report/normalize.go`, `pkg/report/summary.go`, `cmd/felix/assess_cmd.go` | Unified `NormalizeVerificationStatus` mapping (`CONFIRMED -> VERIFIED`, `POTENTIAL -> DETECTED`, `NOT TESTED / NOT VALIDATED -> NOT_VERIFIED`); invoked post-enrichment `DeduplicateFindings`, `Prioritize`, `Summarize`, `RecalculateReportRisk`, and `BuildCommercialReport` after Phase 5/live enrichment. | `TestPhase7_NormalizeVerificationStatusAndSummarySync` |
| **PH7-D08** | `pkg/correlation/fingerprint.go`, `pkg/correlation/dedup.go` | Updated `extractHardeningDiscriminator` and `BuildFingerprint` to discriminate security headers by header name / `f.Title` and distinguish property paths (`property_path`), preventing `HDR-CSP` and `HDR-NOSNIFF` from silently merging. | `TestPhase7_DistinctSecurityHeadersDoNotDeduplicate` |
| **PH7-D09** | `pkg/investigation/prover.go`, `pkg/investigation/types.go` | Fixed `FormatSafeCurl` call sites to resolve `f.Endpoint` against `f.Target` rather than truncating to root `f.Target`. | `TestPhase7_SafeCurlResolvesSubpathTargetCleanly` |
| **PH7-D11** | `pkg/investigation/prover.go`, `pkg/investigation/retest.go`, `pkg/investigation/live_session.go` | Preserved `cleanup_status`, added concrete live provers (`CMDI`, headers, clickjacking, info disclosure, BOLA/BOPLA), and ensured `--retest` never emits false `FIX DETECTED` on untested or potential categories. | `TestPhase7_RetestNeverClaimsFixOnUntestedOrPotential`, `TestPhase7_RetestLiveProvers_CMDI_Headers_Info_Authz` |

---

## 3. Empirical Cross-Format Parity & Evidence Audit (Phase 6 vs. Phase 7)

### 3.1 Summary Count, Commercial Sync & SARIF/HTML Parity

| Run | Metric | Phase 6 Value | Phase 7 Value | Status |
| :--- | :--- | :---: | :---: | :--- |
| **VAmPI `v4_multirole_mut`** | `summary.total_findings` vs `len(findings)` vs SARIF `results` | `3` vs `4` vs `4` (MISMATCH) | **`7` vs `7` vs `7`** | **100% Parity** |
| **VAmPI `v4_multirole_mut`** | Commercial report false zero-findings banner | `true` (Contradiction) | **`false`** (`verified=6, detected=1`) | **Fixed** |
| **VAmPI `v4_multirole_mut`** | HTML report missing finding titles | N/A | **`0` missing (`164,298` bytes)** | **Verified** |
| **VAmPI `v6_ui_multirole_mut`** | JSON vs `summary.total_findings` vs SARIF | `3` vs `4` vs `4` (MISMATCH) | **`7` vs `7` vs `7`** | **100% Parity** |
| **Juice Shop `j4_multirole_mut`** | JSON vs `summary.total_findings` vs SARIF | `26` vs `26` vs `26` (24 CMDI FPs) | **`7` vs `7` vs `7`** (`verified=1, detected=6`) | **100% Parity** |
| **Juice Shop `j4_multirole_mut`** | HTML report missing finding titles | N/A | **`0` missing (`179,348` bytes)** | **Verified** |
| **crAPI `c4_multirole_mut`** | `summary.total_findings` vs `len(findings)` vs SARIF | `12` vs `13` vs `13` (MISMATCH) | **`5` vs `5` vs `5`** (`verified=4, detected=1`) | **100% Parity** |
| **crAPI `c4_multirole_mut`** | Commercial report false zero-findings banner | `true` (Contradiction) | **`false`** | **Fixed** |
| **crAPI `c4_multirole_mut`** | HTML report missing finding titles | N/A | **`0` missing (`143,787` bytes)** | **Verified** |

*(Also confirmed `summary.total_findings == len(findings)` across every single Phase 7 run: `v1` `4/4`, `v2a` `5/5`, `v3` `9/9`, `v4` `7/7`, `v5` `4/4`, `v6` `7/7`, `j1` `2/2`, `j2` `2/2`, `j3` `7/7`, `j4` `7/7`, `j5` `2/2`, `c1` `4/4`, `c2` `4/4`, `c3` `4/4`, `c4` `5/5`, `c5` `4/4`.)*

### 3.2 Concrete Endpoint `safe_curl_command` & Provenance Verification

Inspecting `phase7_runs` output artifacts confirmed exact endpoint preservation and SHA-256 content provenance digests:
- VAmPI `v4` BOLA finding: `safe_curl_command = curl -i -s -X GET "http://127.0.0.1:5000/books/v1/%7Bbook_title%7D"` (previously root `http://127.0.0.1:5000`).
- VAmPI `v4` BOPLA / BFLA findings: `safe_curl_command = curl -i -s -X GET "http://127.0.0.1:5000/users/v1/_debug"`.
- VAmPI `v6` (`/ui/` non-root target): header/recon curl commands resolve cleanly to `"http://127.0.0.1:5000/ui/"`, while OpenAPI authz findings resolve to `"http://127.0.0.1:5000/books/v1/%7Bbook_title%7D"` and `"http://127.0.0.1:5000/users/v1/_debug"`.
- crAPI `c4` info disclosure: `safe_curl_command = curl -i -s -X GET "http://127.0.0.1:8888/.env"` with SHA-256 digest provenance (`ev_fc908350e0b1eb329d8c3c44`, `sha256:4c603a99...`).

### 3.3 Secret Redaction & Honest `--safe` / `--retest` Classification

- **Zero Leaked Secrets on crAPI `/.env`:** crAPI serves a real `.env` file containing database credentials. Under `--synthetic-fixture --fixture-hosts 127.0.0.1:8888`, FELIX verified the exposed `.env` configuration signature and persisted `"Synthetic test fixture verified exposed configuration file signature on /.env (all secrets redacted)"` with **0 cleartext secrets** across `assessment_report.json`, `investigated_findings.json`, and `authorization_summary.json`.
- **Zero False `"NOT TESTED"` Contradictions:** Non-`--safe` mutating campaigns eliminated Phase 6's `NOT TESTED` labels across verified findings (`v4`: `6 VERIFIED`, `1 NOT_VERIFIED` for informational recon summary; `c4`: `4 VERIFIED`, `1 NOT_VERIFIED`).
- **Fail-Closed `--retest` Verdicts:**
  - Phase 6 retests produced `0` still-present verdicts (`inconclusive=4/4` on VAmPI, `26/26` on Juice Shop, `13/13` on crAPI).
  - Phase 7 retests actively reproduced live persisting issues (`VULNERABILITY STILL PRESENT`: `3` on VAmPI `v7`, `1` on Juice Shop `j6`, `3` on crAPI `c6`), held `0` false `FIXED` verdicts, and failed closed to `RETEST INCONCLUSIVE` with explicit reasons where secondary identity headers (`v7` BOLA/BOPLA/BFLA) or bounded unauthenticated static checks (`j6` `POTENTIAL` BFLA, `c6` `/.env` without unauthenticated fixture proof) could not prove remediation.

### 3.4 Residual Observation

In Juice Shop `j4_multirole_mut`, the 5 `DETECTED` (`POTENTIAL`) BFLA findings currently emit `safe_curl_command: ""` in `assessment_report.json` because `POTENTIAL` candidates without confirmed cross-role exploit proof omit an active verification `safe_curl_command` (only confirmed/investigated findings receive verified replay commands, though adding a neutral reproducibility probe for `DETECTED` BFLA findings is a minor future improvement).
