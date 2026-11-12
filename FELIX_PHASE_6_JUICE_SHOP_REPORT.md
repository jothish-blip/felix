# FELIX — PHASE 6: OWASP JUICE SHOP VALIDATION REPORT

**Target Application:** OWASP Juice Shop `v20.2.0` (`C:\SecurityLabs\juice-shop-package\juice-shop_20.2.0`)  
**Endpoint:** `http://127.0.0.1:3000` (Native Windows Node.js `v24.20.0`, `node build/app`)  
**Host Isolation:** Windows Firewall active across Domain/Private/Public profiles with zero Node.js allow rules  
**FELIX Binary Tested:** Isolated build from `C:\Jothish\felix` `HEAD` (`4fc8c8e`)  
**Campaign Scope:** Campaigns `J1`–`J6` (`j1_unauth_full` through `j6_retest`)  
**Testing Stance:** Strictly blind CLI execution targeting only `http://127.0.0.1:3000`.

---

## 1. Deployment & Pre-Scan Verification

Synthetic test accounts and pre-scan checks verified against live `http://127.0.0.1:3000` (`challenges.yml`: `116` total challenges across `16` categories):

1. **Synthetic Identities Seeded:**
   - `user_a`: `p6usera@juice-sh.op` (`bid=6`, seeded cart items)
   - `user_b`: `p6userb@juice-sh.op` (`bid=7`, seeded cart items)
   - `admin`: `p6admin@juice-sh.op` (`bid=8`, created via `POST /api/Users` with `"role": "admin"` verifying `JS-GT-05` BOPLA mass assignment)
2. **Ground-Truth Pre-Check Observations:**
   - `GET /rest/basket/7` as `user_a` -> `HTTP 200` (`JS-GT-04` cross-user basket BOLA confirmed live)
   - `GET /api/Users` unauthenticated & `DELETE /api/Products/1` as customer -> `HTTP 401` (`JS-GT-10` negative controls)
   - `GET /.env` -> `HTTP 200 text/html` Angular `index.html` SPA catch-all (`JS-GT-09` negative control)
   - `GET /redirect?to=https://evil.example` -> `HTTP 406 Unacceptable` (`JS-GT-08` allowlist negative control)
   - `GET /` response headers: `Access-Control-Allow-Origin: *` (no `Access-Control-Allow-Credentials`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, missing `Content-Security-Policy`.

---

## 2. Campaign Execution Matrix (`J1`–`J6`)

| Campaign | Profile / Mode | Exit | Wall Time (s) | FELIX Dur (ms) | Peak RAM (MB) | Findings (`CRITICAL / Med / Info`) | Risk Score / Level | Authz Objects (`Executed / Inconclusive`) |
|---|---|---:|---:|---:|---:|---|---|---|
| `J1` (`j1_unauth_full`) | `full`, anonymous | `1` | `17.393` | `15978` | `84.05` | `26` (`24` CRIT, `1` Med, `1` Info) | `52 / MEDIUM` | `30` (`0 / 0`, `NOT_CONFIGURED`) |
| `J2` (`j2_usera_full`) | `full`, `--auth` (`user_a`) | `1` | `26.347` | `25184` | `85.40` | `26` (`24` CRIT, `1` Med, `1` Info) | `52 / MEDIUM` | `30` (`0 / 0`, `PARTIAL`) |
| `J3` (`j3_multirole_ro`) | `api`, `--roles-config` (RO) | `0` | `3.494` | `3110` | `111.35` | `2` (`0` CRIT, `1` Med, `1` Info) | `4 / INFORMATIONAL` | `30` (`30 / 30`) |
| `J4` (`j4_multirole_mut`) | `full`, `--roles-config`, mutating | `1` | `18.794` | `17782` | `102.41` | `26` (`24` CRIT, `1` Med, `1` Info) | `52 / MEDIUM` | `30` (`30 / 30`) |
| `J5` (`j5_safe_neg`) | `full`, `--safe` | `0` | `1.919` | `1714` | `83.58` | `2` (`0` CRIT, `1` Med, `1` Info) | `4 / INFORMATIONAL` | `30` (`0 / 0`, `NOT_CONFIGURED`) |
| `J6` (`j6_retest`) | `--retest j4.../assessment_report.json` | `0` | `0.713` | — | `33.94` | — | — | `26/26 INCONCLUSIVE` |

*(Exit code `1` occurs whenever FELIX detects one or more `CRITICAL` or `HIGH` findings; `0` otherwise.)*

---

## 3. True Positives & Validated Negative Controls

### 3.1 Genuine Findings & Asset Discovery
- **Missing `Content-Security-Policy` (`Medium`, TP — `JS-GT-11`):** Accurately identified in every campaign (`J1`–`J5`). Unlike VAmPI and crAPI, FELIX checked the `GET /` headers and saw both `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN`, so it emitted only CSP (`1` finding instead of `3`).
- **SPA JS Bundle Asset Extraction (`JS-GT-13`, Partial):** Crawler discovered root HTML plus compiled Angular bundles (`main.js`, `polyfills.js`, `scripts.js`, `styles.css` — `12` JS bundle observations across 4 identities in `J3`/`J4`) and extracted `6` API candidates per identity (`24` total across 4 identities; `56` total assets tracked in `coverage_matrix.json`):
  - `/api/Cards`
  - `/api/Challenges`
  - `/api/Challenges?key=[REDACTED]` *(query parameter name `key` automatically redacted by FELIX)*
  - `/api/Deliverys`
  - `/api/Feedbacks`
  - `/api/Hints`

### 3.2 Negative Controls Directly Validated (Tested True Negatives)
1. **Present Security Headers (`JS-GT-11`):** Neither `X-Content-Type-Options: nosniff` nor `X-Frame-Options: SAMEORIGIN` was falsely flagged.
2. **SPA `200 OK` HTML Catch-All (`JS-GT-09`):** `webvuln` probed `/.env`, `/.git/config`, and related paths against `http://127.0.0.1:3000` where Juice Shop returns `200 text/html` (`<app-root></app-root>`), and accurately suppressed false disclosure findings (`0` `WV-INFODISC` FPs).
3. **Wildcard Non-Credentialed CORS (`JS-GT-12`):** Presence of `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` did not trigger a false Critical/High credentialed CORS bypass (`cors`: `0` FPs).
4. **Public Object Ambiguity Guardrail (`BOLA`):** Across `J3` and `J4`, FELIX discovered `30` parameterized `/api/Challenges/{id}` objects and executed `30` cross-identity probes (`requests_sent: 28` in `authz`), marking all `30/30` **`INCONCLUSIVE`** (`determinative_outcome_pct: 0%`) due to unestablished object ownership rather than claiming `30` false BOLA alerts on `HTTP 200` catalog records.
5. **Safe Mode (`J5` `--safe`):** Properly suppressed active injection probes, dropping runtime from `18.794s` (`J4`) to `1.919s` (`J5`) and eliminating all `24` active `CMDI` FPs.

---

## 4. Critical Defect — 24 False Positive `CRITICAL` OS Command Injection Findings

In `J1`, `J2`, and `J4`, FELIX reported **`24` `CRITICAL` `WV-CMDI / OS Command Injection` findings**:
- **Matrix:** `8` parameter names (`cmd`, `command`, `exec`, `run`, `ping`, `host`, `ip`, `username`) x `3` GET URLs (`/api/Challenges`, `/api/Hints`, `/polyfills.js`) = `24` findings.
- **Root Cause Verified (`pkg/webvuln/engine.go:788`):**
  The active `webvuln` CMDI check sends `GET <url>?<param>=whoami` and scans response bodies for static OS indicator substrings (`"root"`, `"uid="`, `"www-data"`, `"system"`, `"windows"`, etc.) without verifying whether those substrings were already present in the baseline unparameterized response:
  - `GET /api/Challenges` contains challenge descriptions including the literal words `"system"` and `"windows"`.
  - `GET /api/Hints` contains hint strings including `"system"`.
  - `GET /polyfills.js` contains `"root"`.
- **Internal Contradiction Across Reports:**
  - `top_priorities` and `summary` list all `24` CMDI findings as `verified_count: 24` (`CONFIRMED`, score `40/40`, observation: `"Confirmed OS command execution output in response via parameter ... (whoami probe returned active account)"`).
  - Meanwhile, inside `findings[]` and `investigated_findings.json`, all `24` items have `verification.status: "NOT TESTED"` and `proof_summary: "No safe bounded automated proof procedure exists for this category. Finding retained as POTENTIAL."`.
  - Furthermore, `commercial_report.executive_summary` states `severity_distribution: {"CRITICAL": 24}`, `findings_verified_count: 24`, yet sets `risk_level: "MEDIUM"` (`risk_score: 52/100`), `key_concerns: ["No Critical or High severity exposures were verified during assessment execution."]`, and `posture_statement: "No security findings were identified within the evaluated scope..."`.

---

## 5. False Negatives & Discovery Blind Spots

Despite scanning an application with `116` documented challenges:
- **Missed `/rest/*` API & App Surface (`JS-GT-01`..`08`, `JS-GT-13`):** The Angular JS extractor extracted `/api/*` paths matching simple URL patterns but missed `/rest/products/search`, `/rest/user/login`, `/rest/basket/{id}`, `/rest/user/whoami`, `/profile/image/url`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, `/api-docs`, and `/redirect`.
- **Resulting False Negatives:** SQL injection (`JS-GT-01`, `JS-GT-02`), Angular `#/search` DOM XSS (`JS-GT-03`), basket BOLA (`JS-GT-04`), `/api/Users` role mass assignment (`JS-GT-05`), SSRF (`JS-GT-06`), exposed `/ftp`/`/metrics`/`/encryptionkeys`/`/api-docs` (`JS-GT-07`), and redirect allowlist bypass (`JS-GT-08`).
- **Retest (`J6`):** `26/26` baseline findings yielded `RETEST INCONCLUSIVE` (`0.713s`) because FELIX's retest dispatcher cannot replay `NOT TESTED` `header`/`CMDI` records.
- **Secret Handling:** `0` JWT tokens or synthetic passwords leaked in any FELIX-generated output artifact.
