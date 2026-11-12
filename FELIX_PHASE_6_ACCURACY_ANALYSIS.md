# FELIX — PHASE 6: ASSESSMENT ACCURACY & PRECISION/RECALL ANALYSIS

**Baseline Assessed:** `C:\Jothish\felix` (`HEAD` `4fc8c8e`, Windows build)  
**Measurement Rules:**
- Metrics are reported **strictly per application and per vulnerability class**. Incompatible targets (REST OpenAPI service vs Angular SPA vs microservice gateway) and verification tiers are **never merged** into an opaque single aggregate.
- **Discovery informational observations** (`Attack Surface Discovery`, `Info`, score `0/40`) are tracked under discovery coverage and **excluded** from vulnerability TP/FP numerator inflation.
- **Untested Negative Controls** (endpoints never discovered/probed by FELIX) are separated from **Evaluated Negative Controls (`Tested TN`)** so Specificity is never artificially inflated.
- Both **Full Mutating Multi-Role (`V4`, `J4`, `C4`)** and **Safe / Read-Only Profiles (`V5`, `J3`/`J5`, `C3`/`C5`)** are reported to show the empirical effect of the `webvuln` CMDI bug.

---

## 1. Per-Application Confusion Matrix & Diagnostic Metrics

### 1.1 Full Multi-Role Assessment (`V4`, `J4`, `C4`)

| Target (Run) | Granularity / Scope | TP | FP | FN | Tested TN | Untested Neg. Controls | Precision | Recall | Tested Specificity | FPR | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **VAmPI (`V4`)** | Finding-level (includes `3` missing headers `VAMPI-GT-10`) | `3` | `0` | `6` | `2` | `3` | `100.0%` | `33.3%` | `100.0%` | `0.0%` | `50.0%` |
| **VAmPI (`V4`)** | GT-row level (`VAMPI-GT-10` counted as `1` row) | `1` | `0` | `6` | `2` | `3` | `100.0%` | `14.3%` | `100.0%` | `0.0%` | `25.0%` |
| **OWASP Juice Shop (`J4`)** | Pre-registered GT (`JS-GT-01..08`, `JS-GT-11` CSP + Tested TNs) | `1` | `24` | `8` | `4` | `1` | `4.0%` | `11.1%` | `14.3%` | `85.7%` | `5.9%` |
| **OWASP crAPI (`C4`)** | Live-verified vulnerabilities (includes `/.env` + `3` missing headers) | `4` | `8` | `10` | `3` | `1` | `33.3%` | `28.6%` | `27.3%` | `72.7%` | `30.8%` |
| **OWASP crAPI (`C4`)** | Strict pre-scan GT register only (`CRAPI-GT-01..10`) | `0` | `8` | `10` | `3` | `1` | `0.0%` | `0.0%` | `27.3%` | `72.7%` | `0.0%` |

*(Note: On Juice Shop `J3`/`J4`, `30` BOLA probes on `/api/Challenges/{id}` returned `INCONCLUSIVE`, so they contributed `0` FPs and `0` TPs/TNs.)*

### 1.2 Safe Mode & API-Only Profiles (`V5`, `J3`, `J5`, `C3`, `C5`)

When active `webvuln` injection probes are disabled (`--safe` or `--profile api`):

| Target (Run) | Profile | TP | FP | FN | Tested TN | Precision | Recall | Tested Specificity | FPR | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **VAmPI (`V5`)** | `--safe` | `3` | `0` | `6` | `2` | `100.0%` | `33.3%` | `100.0%` | `0.0%` | `50.0%` |
| **Juice Shop (`J5`)** | `--safe` | `1` | `0` | `8` | `4` | `100.0%` | `11.1%` | `100.0%` | `0.0%` | `20.0%` |
| **crAPI (`C5`)** | `--safe` (`/.env` skipped) | `3` | `0` | `11` | `2` | `100.0%` | `21.4%` | `100.0%` | `0.0%` | `35.3%` |

**Key Takeaway:** All `32` False Positives observed across Phase 6 (`24` on Juice Shop, `8` on crAPI) originate from a **single defect** in `webvuln`'s active OS command injection check (`WV-CMDI`). Without that single bug, active assessment precision across tested classes would have been `100%` (`8 TP / 0 FP`), though recall remains low (`11.1%`–`33.3%`) due to API/SPA discovery blind spots.

---

## 2. Per-Vulnerability-Class Breakdown

| Vulnerability Class | Applicable Live Targets | Expected Cases | Detected (`TP`) | False Positives (`FP`) | Missed (`FN`) | Tested `TN` | Class Precision | Class Recall | Notes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| **Security Headers (`CSP`, `XFO`, `nosniff`)** | VAmPI (`3`), Juice Shop (`1` gap, `2` present), crAPI (`3`) | `7` | `7` | `0` | `0` | `2` | `100.0%` | `100.0%` | Accurately passed Juice Shop's `nosniff` & `SAMEORIGIN` (`2/2 TN`) and caught all `7` missing headers; marred only by `summary` deduplication undercounting `X-Content-Type-Options`. |
| **Sensitive Configuration Exposure (`/.env`, `/_debug`, `/ftp`, etc.)** | VAmPI (`_debug`), Juice Shop (`/ftp`, `/metrics`, etc.; `/.env` SPA TN), crAPI (`/.env` live; `/.git/config` `404` TN) | `3` (`_debug`, `/ftp..`, `crapi/.env`) | `1` | `0` | `2` | `2` | `100.0%` | `33.3%` | Detected real `crapi /.env` (`HIGH`) with secrets redacted while cleanly rejecting Juice Shop's `200 OK` HTML catch-all (`/.env`) and crAPI `404` `/.git/config`. Missed VAmPI `_debug` & Juice Shop `/ftp`. |
| **CORS Policy** | Juice Shop (`ACAO: *` without `ACAC`, negative control for Crit bypass), VAmPI, crAPI | `0` Crit | `0` | `0` | `0` | `3` | `N/A` | `N/A` | Never falsely escalated non-credentialed `ACAO: *` to Critical/High. |
| **OS Command Injection (`WV-CMDI`)** | None (`0` true targets on root/API endpoints probed) | `0` | `0` | `32` | `0` | `1` (VAmPI) | `0.0%` | `N/A` | `24` Critical FPs on Juice Shop (`/api/Challenges`, `/api/Hints`, `/polyfills.js`), `8` Critical FPs on crAPI (`/`). |
| **BOLA / IDOR** | VAmPI (`books`), Juice Shop (`basket`), crAPI (`vehicle location`, `mechanic_report`) | `4` | `0` | `0` | `4` | `0` tested (`30` `INCONCLUSIVE`) | `N/A` | `0.0%` | Juice Shop `/api/Challenges/{id}` evaluated `30` objects (`all INCONCLUSIVE` — safe guardrail). VAmPI & crAPI discovered `0` objects. |
| **BFLA** | VAmPI (`password`), crAPI (`admin/videos`, `management/users/all`) | `3` | `0` | `0` | `3` | `0` tested | `N/A` | `0.0%` | `functions_discovered = 0` across all 3 apps (crAPI also lacked admin persona via public signup). |
| **BOPLA / Mass Assignment** | VAmPI (`register`), Juice Shop (`api/Users`), crAPI (`videos`) | `3` | `0` | `0` | `3` | `0` tested | `N/A` | `0.0%` | `properties_discovered = 0` across all 3 apps. |
| **SQLi / NoSQLi** | VAmPI (`ADMIN` SQLi), Juice Shop (`search`, `login`), crAPI (`validate-coupon`) | `4` | `0` | `0` | `4` | `0` tested | `N/A` | `0.0%` | Endpoints never discovered in crawl/OpenAPI pipeline. |
| **DOM XSS / Reflected XSS** | Juice Shop (`#/search?q=`) | `1` | `0` | `0` | `1` | `1` (JSON/SPA no FP) | `N/A` | `0.0%` | No API JSON XSS FPs, but `/#/search` DOM sink not exercised. |
| **SSRF / Open Redirect / Auth-JWT** | VAmPI (`login`/weak secret), Juice Shop (`SSRF`, `redirect`), crAPI (`SSRF`, `JWT/JWKS`) | `5` | `0` | `0` | `5` | `0` tested | `N/A` | `0.0%` | Blind crawl never reached `/rest/*`, `/workshop/*`, `/identity/*`, or `/.well-known/jwks.json`. |
| **Excluded Destructive Scope** | VAmPI (`/createdb`), crAPI (`DoS/brute-force`) | `0` | `0` | `0` | `0` | `2` | `N/A` | `N/A` | Verified zero DB resets (`database.db` SHA preserved) and zero brute-force/DoS loops. |

---

## 3. Finding Status & Verification Accounting Contradictions

Empirical inspection of `assessment_report.json` (`V4`, `J4`, `C4`) vs `investigated_findings.json` vs `retest_report.json` exposed three reporting consistency defects that directly affect automated accuracy scoring:

1. **Confirmed/Verified Count Contradicts Individual Finding Verification Status:**
   - In `J4`: `summary.verified_count = 24`, `summary.confirmed_count = 26`, `summary.by_status = {"CONFIRMED": 26}`, and `top_priorities[0..4]` show `verification.status = "VERIFIED"` (`score: 40`).
   - Simultaneously, inside the **same JSON file**, all `26` items in `findings[]` and `investigated_findings.json` carry `verification.status = "NOT TESTED"` (`proof_summary: "No safe bounded automated proof procedure exists..."`)!
   - The same divergence occurred on `C4` (`summary.verified_count = 9`, `top_priorities` `VERIFIED`, yet `findings[]` and `investigated_findings.json` `13/13` `"NOT TESTED"` — including the real `/.env` High finding!) and on `V4` (`findings[]` `"NOT TESTED"`, `top_priorities` `"OBSERVED"`).
2. **`summary.total_findings` Deduplication Mismatch on Multi-Header Findings:**
   - On `V4` (`4` items in `findings[]`, `sarif`, and `remediation_roadmap`) and `C4` (`13` items), `summary.total_findings` reported `3` and `12` (`low_count: 1` instead of `2`) because `HDR-CSP` marked `HDR-NOSNIFF` as a merged duplicate (`duplicate_finding_ids`) in summary aggregation without removing it from `findings[]`.
3. **`commercial_report.executive_summary` Boilerplate Disconnected from Critical Findings:**
   - Even when `J4` reported `24 CRITICAL` findings (`score: 52/100`) and `C4` reported `8 CRITICAL + 1 HIGH` (`score: 35/100`), `commercial_report.executive_summary` still emitted:
     - `key_concerns: ["No Critical or High severity exposures were verified during assessment execution."]`
     - `posture_statement: "No security findings were identified within the evaluated scope..."`
4. **Retest Classification Uniformity (`V7`, `J6`, `C6`):**
   - `4/4` (`V7`), `26/26` (`J6`), and `13/13` (`C6`) retested items all returned `RETEST INCONCLUSIVE` because `--retest` only checks verified-proof finding types and cannot replay `NOT TESTED` headers, `/.env`, or CMDI entries.
