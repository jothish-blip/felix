# FELIX PHASE 7 — ACCURACY METRICS & BEFORE/AFTER SCORECARD

**Repository:** `C:\Jothish\felix`  
**Validation Date:** 2026-11-12  

---

## 1. End-to-End Quantitative Scorecard (Phase 6 vs. Phase 7)

All measurements below come directly from recorded `phase6_runs` and `phase7_runs` campaign artifacts on local VAmPI (`127.0.0.1:5000`), OWASP Juice Shop `v20.2.0` (`127.0.0.1:3000`), and OWASP crAPI `v1.1.5` (`127.0.0.1:8888`).

| Accuracy Dimension | Phase 6 Baseline | Phase 7 Remediated | Improvement |
| :--- | :--- | :--- | :--- |
| **CMDI False Positives (All Campaigns)** | `96` (`CRITICAL`) (`j1:24, j2:24, j4:24, c1:8, c2:8, c4:8`) | **`0`** across all 17 runs | **-100% (96 -> 0)** |
| **VAmPI Attack Surface Endpoints (`v4`)** | `1` | **`13`** (`17` on `/ui/` `v6`) | **+1,200%** |
| **Juice Shop Unique Candidates (`j4`)** | `6` (inflated `24` in multi-role) | **`48`** (`66` attack surface) | **+700% unique candidates** |
| **crAPI JS Bundle Candidates (`c4`)** | `0` (`2` attack surface) | **`31`** (`33` attack surface) | **0 -> 31 (+1,550% total surface)** |
| **VAmPI True API Authz Detections (`v4`)** | `0` BOLA / `0` BFLA / `0` BOPLA | **`3` VERIFIED** (`BOLA` `/books/v1/{book_title}`, `BFLA` `/users/v1/_debug`, `BOPLA` `[users[0].password]`) | **0 -> 3 real API vuln classes verified** |
| **VAmPI Read-Only Multi-Role (`v3`)** | `0` verified (`0/4` checks) | **`10` verified authz checks** (`66.7%` determinative outcome, `88.2%` execution coverage) | **Verified cross-user reads** |
| **Summary vs Findings Parity (`summary.total_findings == len(findings)`)** | Failed on VAmPI (`3!=4`) & crAPI (`12!=13`) | **`100%` (`17/17` scans match)** | **Eliminated drift** |
| **JSON vs SARIF Count Parity (`v4`/`j4`/`c4`/`v6`)** | Counts matched un-deduped slice, conflicted with summary | **`100%` (`7/7`, `7/7`, `5/5`, `7/7`)** | **Consistent across JSON/SARIF/HTML** |
| **Commercial Report False "No findings" Banner** | Present on `v4`, `j4`, `c4` (`true`) | **`0` occurrences (`false` on all)** | **Eliminated contradiction** |
| **Findings Marked `"NOT TESTED"` in Active Mutating Runs (`v4`/`j4`/`c4`)** | `100%` (`4/4` VAmPI, `26/26` JS, `13/13` crAPI) | **`0`** (`NOT_VERIFIED` reserved for Recon summary only) | **100% eliminated** |
| **Retest Persisting Vulnerabilities Reproduced (`v7`/`j6`/`c6`)** | `0/43` (`100%` `RETEST INCONCLUSIVE`) | **`7`** (`VULNERABILITY STILL PRESENT`: `3` VAmPI, `1` Juice Shop, `3` crAPI) | **Live header repro working** |
| **Retest False `FIX DETECTED` Rate** | Untested/ambiguous at risk in unit paths | **`0` false fixes** | **Fail-closed guaranteed** |
| **Cleartext Secrets Leaked in Exposed crAPI `/.env` Report** | Unredacted synthetic handling risk | **`0` cleartext secrets (`leaks: []`)** | **Strict redaction verified** |

---

## 2. Target-by-Target Summary Matrix (`phase7_runs`)

### 2.1 OWASP VAmPI (`127.0.0.1:5000`)
- `v1_unauth_full`: `4` findings (`3 VERIFIED`, `1 NOT_VERIFIED` recon), `cmdi=0`, `authz(obj=6,fn=5,prop=1)`, summary parity `4==4`.
- `v2a_usera_full`: `5` findings (`4 VERIFIED`, including `BOPLA /users/v1/_debug [users[0].password]`), `cmdi=0`, summary parity `5==5`.
- `v3_multirole_ro`: `9` findings (`8 VERIFIED` including 3 book BOLA reads, BOPLA, BFLA, 3 headers; `1 NOT_VERIFIED` recon), `authz reqs=51`, `30/34` checks executed (`88.2%`), `10` verified authz checks, `10` not_vulnerable, `10` inconclusive, summary parity `9==9`.
- `v4_multirole_mut`: `7` findings (`6 VERIFIED` including BOLA `/books/v1/{book_title}`, BOPLA `/users/v1/_debug [users[0].password]`, BFLA `GET /users/v1/_debug`, 3 headers; `1 NOT_VERIFIED` recon), `31/32` authz checks executed (`96.9%`), `1` destructive skipped (`/users/v1/{username}` / `/createdb` guard), `1` attack path + `1` security story correlated, summary parity `7==7`.
- `v5_safe_neg`: `4` findings (`4 VERIFIED`), `0` active probes, `0` CMDI, summary parity `4==4`.
- `v6_ui_multirole_mut` (`--target http://127.0.0.1:5000/ui/`): `7` findings (`6 VERIFIED` matching `v4`), discovered **`17`** endpoints from subpath root, summary parity `7==7`.
- `v7_retest`: `7` retested -> `still_present=3` (`HDR-CSP`, `HDR-XFO`, `HDR-NOSNIFF`), `fixed=0`, `inconclusive=4` (`BOLA`, `BOPLA`, `BFLA` requiring secondary identity creds in single-header replay, `RECON-INFO`), `regression=0`.

### 2.2 OWASP Juice Shop `v20.2.0` (`127.0.0.1:3000`)
- `j1_unauth_full` / `j2_usera_full`: `2` findings (`1 VERIFIED` `HDR-CSP`, `1 NOT_VERIFIED` recon `66` endpoints), `cand=48`, **`cmdi=0`** (down from `24`).
- `j3_multirole_ro` / `j4_multirole_mut`: `7` findings (`1 VERIFIED` `HDR-CSP`, `5 DETECTED` `MEDIUM` BFLA candidates on `/api/Addresss`, `/api/Cards`, `/api/Products`, `/api/Users`, `/rest/captcha`, `1 NOT_VERIFIED` recon `66` endpoints), `111/111` authz checks executed (`100%`, `17` `not_vulnerable`, `12` `candidate`, `82` `inconclusive`, `2` destructive excluded), **`cmdi=0`**, summary parity `7==7`.
- `j5_safe_neg`: `2` findings (`2 VERIFIED`), `0` active probes, `66` discovered surface, summary parity `2==2`.
- `j6_retest`: `7` retested -> `still_present=1` (`HDR-CSP`), `fixed=0`, `inconclusive=6` (`5 POTENTIAL BFLA` + `1 RECON-INFO`), `regression=0`.

### 2.3 OWASP crAPI `v1.1.5` (`127.0.0.1:8888`)
- `c1_unauth_full` / `c2_usera_full` / `c3_multirole_ro`: `4` findings (`3 VERIFIED` headers `HDR-CSP`, `HDR-XFO`, `HDR-NOSNIFF`, `1 NOT_VERIFIED` recon `33` endpoints), `cand=31`, **`cmdi=0`** (down from `8`), summary parity `4==4`.
- `c4_multirole_mut`: `5` findings (`4 VERIFIED` including `HIGH` `/.env` disclosure with redacted secrets + `3` headers; `1 NOT_VERIFIED` recon `33` endpoints), `1` attack path + `1` security story, `21/21` authz checks executed (`inconclusive=21`), summary parity `5==5`.
- `c5_safe_neg`: `4` findings (`4 VERIFIED`), `0` active probes, summary parity `4==4`.
- `c6_retest`: `5` retested -> `still_present=3` (3 headers), `fixed=0`, `inconclusive=2` (`/.env` unauthenticated safety boundary + `RECON-INFO`), `regression=0`.
