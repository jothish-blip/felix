# FELIX — PHASE 6: VAmPI VALIDATION REPORT

**Target Application:** VAmPI (Vulnerable REST API) — Local Commit `f16052d` with pre-existing local patch (`api_views/users.py`, `app.py`)  
**Endpoint:** `http://127.0.0.1:5000` (Flask / Werkzeug `2.2.3`, Python `3.12.10` in `C:\SecurityLabs\vampi`)  
**FELIX Binary Tested:** Isolated build from `C:\Jothish\felix` `HEAD` (`4fc8c8e`)  
**Campaign Scope:** Campaigns `V1`–`V7` (`v1_unauth_full` through `v7_retest`)  
**Testing Stance:** Strictly blind CLI execution targeting only base URLs (`http://127.0.0.1:5000` and `http://127.0.0.1:5000/ui/`) with no hardcoded target route hints.

---

## 1. Deployment & Pre-Scan Verification

Before launching FELIX, VAmPI was started locally bound strictly to loopback (`127.0.0.1:5000`, `alive=86400`, `debug=False`):

1. **Database Baseline Integrity:** Original `C:\SecurityLabs\vampi\database\database.db` was hashed (`SHA256=4599BBD4AF03491CDA7CA941B2AA28CD42836858BC6CB3478276C1ECC6DB02BD`) and backed up before seeding synthetic Phase 6 accounts.
2. **Synthetic Identities & Objects Seeded:**
   - `user_a`: `p6usera` (`ROLE_USER` equivalent, book `p6_alpha_diary` with synthetic secret)
   - `user_b`: `p6userb` (`ROLE_USER` equivalent, book `p6_beta_ledger` with synthetic secret)
   - `admin`: pre-seeded VAmPI `admin` account (`admin` token included in `vampi_roles.json`)
3. **Ground-Truth Pre-Check Observations:**
   - `GET /books/v1/p6_beta_ledger` as `user_a` -> `HTTP 200` returning `user_b`'s secret (`VAMPI-GT-02` vulnerable BOLA confirmed)
   - `GET /users/v1/p6userb` as `user_a` -> `HTTP 403` (`VAMPI-GT-03` local security patch confirmed)
   - `DELETE /users/v1/p6userb` as `user_a` -> `HTTP 401` (`VAMPI-GT-07` admin enforcement negative control confirmed)
   - `GET /openapi.json` -> `HTTP 200` returning `12,613` bytes of OpenAPI `3.0.1` JSON (`VAMPI-GT-10`)
   - `GET /` response headers -> `Content-Type: application/json`; missing `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy`.

---

## 2. Campaign Execution Matrix (`V1`–`V7`)

| Campaign | Profile / Mode | Target URL | Exit | Wall Time (s) | FELIX Dur (ms) | Peak RAM (MB) | `findings[]` Len | `summary.total_findings` | Risk Score / Level |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| `V1` (`v1_unauth_full`) | `full`, anonymous | `http://127.0.0.1:5000` | `0` | `0.412` | `217` | `27.42` | `4` | `3` | `7 / INFORMATIONAL` |
| `V2a` (`v2a_usera_full`) | `full`, `--auth` (`user_a`) | `http://127.0.0.1:5000` | `0` | `0.412` | `213` | `27.45` | `4` | `3` | `7 / INFORMATIONAL` |
| `V2b` (`v2b_userb_full`) | `full`, `--auth` (`user_b`) | `http://127.0.0.1:5000` | `0` | `0.415` | `220` | `28.53` | `4` | `3` | `7 / INFORMATIONAL` |
| `V3` (`v3_multirole_ro`) | `api`, `--roles-config` (RO) | `http://127.0.0.1:5000` | `0` | `0.314` | `75` | `26.76` | `4` | `3` | `7 / INFORMATIONAL` |
| `V4` (`v4_multirole_mut`) | `full`, `--roles-config`, `--allow-state-changing --synthetic-fixture` | `http://127.0.0.1:5000` | `0` | `0.409` | `245` | `28.75` | `4` | `3` | `7 / INFORMATIONAL` |
| `V5` (`v5_safe_neg`) | `full`, `--safe` | `http://127.0.0.1:5000` | `0` | `0.209` | `17` | `26.60` | `4` | `3` | `7 / INFORMATIONAL` |
| `V6` (`v6_ui_multirole_mut`) | `full`, `--roles-config`, mutating | `http://127.0.0.1:5000/ui/` | `0` | `3.424` | `3265` | `63.43` | `4` | `3` | `7 / INFORMATIONAL` |
| `V7` (`v7_retest`) | `--retest v4.../assessment_report.json` | `http://127.0.0.1:5000` | `0` | `0.109` | — | `22.80` | — | — | `4/4 INCONCLUSIVE` |

---

## 3. Discovery, Authorization & Module Coverage Findings

### 3.1 Observed Findings (`V1`–`V6` identical security findings)
Across all active and safe runs (`V1`–`V6`), FELIX emitted the same 4 items inside `findings[]` and `assessment_report.sarif`:

1. `Missing Content-Security-Policy (CSP)` — `Medium` (`HDR-CSP-*`) — **True Positive (`VAMPI-GT-10`)**
2. `Missing Anti-Clickjacking Header (X-Frame-Options)` — `Low` (`HDR-XFO-*`) — **True Positive (`VAMPI-GT-10`)**
3. `Missing or Misconfigured X-Content-Type-Options` — `Low` (`HDR-NOSNIFF-*`) — **True Positive (`VAMPI-GT-10`)**
4. `Discovered 1 attack surface endpoints on 127.0.0.1` (`3` endpoints in `V6`) — `Info` (Attack Surface Discovery inventory note, score `0/40`, not a vulnerability)

### 3.2 Critical Defect #1 — OpenAPI Specification Fetched (`200 OK`) but Ignored by API/Authz Engines
In server logs (`task-44857.log`), FELIX's authorization pre-flight `ensureAuthzDiscovery` explicitly requested `GET /openapi.json`, and VAmPI returned **`HTTP 200` (`12,613` bytes, OpenAPI 3.0.1)**:
- Despite receiving the full OpenAPI 3.0.1 schema describing `/users/v1`, `/users/v1/_debug`, `/users/v1/register`, `/users/v1/login`, `/users/v1/{username}`, `/users/v1/{username}/password`, `/users/v1/{username}/email`, `/books/v1`, and `/books/v1/{book}`, `V4` recorded:
  - `discovery_summary.json`: `total_confirmed_endpoints: 4` (solely `GET /` evaluated once per configured identity: `ANONYMOUS`, `USER_A`, `USER_B`, `ADMIN`), `total_endpoint_candidates: 0`, `total_pages_discovered: 0`.
  - `apisec` module: `0` findings.
  - `authorization_summary.json`: `status: "TESTED"`, `requests_sent: 4`, `objects_discovered: 0`, `functions_discovered: 0`, `properties_discovered: 0`, `total_checks_planned: 0`, `total_checks_executed: 0`.
- **Consequence:** Every API-layer ground-truth vulnerability in VAmPI (`VAMPI-GT-01` `_debug` credential leak, `VAMPI-GT-02` Book BOLA, `VAMPI-GT-04` Register `"admin": true` BOPLA, `VAMPI-GT-05` cross-user password change, `VAMPI-GT-08` login user enumeration / weak JWT secret, and `VAMPI-GT-09` admin-gated SQLi) resulted in **False Negatives**.

### 3.3 Defect #2 — Non-Root Base URL Path Duplication (`V6: /ui/`)
When pointed at `http://127.0.0.1:5000/ui/`, FELIX discovered `4` pages (`GET /ui/` across 4 identities) and `8` Swagger UI JavaScript/CSS asset references (`total_static_assets: 12`, `12` crawl requests), **but** doubled the base path during well-known and asset probing:
- Server logs (`task-44857.log:517-755`) confirmed requests to `/ui/ui/*` and `/ui/openapi.json` returning `HTTP 404`, missing both Swagger's embedded spec URL and the root `/openapi.json`.

### 3.4 Defect #3 — Summary Accounting vs `findings[]` Array Mismatch (`4` vs `3`)
Across `V1`–`V6`:
- `findings[]` in `assessment_report.json`, `investigated_findings.json`, `remediation_roadmap.json`, and `assessment_report.sarif` all contain **`4` items** (`1 Info`, `2 Low`, `1 Medium`).
- However, `assessment_report.json`'s `summary` and `commercial_report.executive_summary` report `total_findings: 3`, `low_count: 1` (instead of `2`), `confirmed_count: 3`.
- Inspection of the CSP finding metadata (`HDR-CSP-fd0038a2` in `top_priorities`) shows `duplicate_count: "1"` and `duplicate_finding_ids: "HDR-NOSNIFF-ee0b625d"`, proving the deduplicator counted `HDR-NOSNIFF` as merged into `HDR-CSP` when computing `summary` counters while leaving both header findings inside `findings[]`, SARIF, and remediation tasks.

### 3.5 Verification Status & Retest Behavior (`V1`–`V7`)
- In `V1`–`V4` and `V6`, all 4 items in `findings[]` were assigned `verification.status: "NOT TESTED"` with Phase 5 `test_identifier: "UNTESTED_CATEGORY_PROCEDURE"`, while `summary.by_status` simultaneously reported `{"CONFIRMED": 3}` and `top_priorities` reported `verification.status: "OBSERVED"`.
- In `--safe` mode (`V5`), `verification.status` switched to `"HIGH CONFIDENCE"` (`test_identifier: "SAFE_MODE_INSPECTION"`), `requests_sent` in `authz` dropped to `0`, and runtime dropped to `0.209s`.
- In `V7` (`--retest`), all `4` baseline findings reported `original_status: "NOT TESTED"` and yielded `4/4` `RETEST INCONCLUSIVE` (`fixed_count: 0`, `still_present_count: 0`).

---

## 4. Safety Controls, Token Redaction & Database Restoration

- **False Positives:** `0` across all 8 VAmPI campaigns (`V1`–`V7`), including zero webvuln CMDI/env false positives on `GET /`.
- **Excluded Scope (`VAMPI-GT-11`):** `GET /createdb` was never executed; post-scan `GET /users/v1/_debug` and `GET /books/v1` confirmed synthetic test rows remained completely intact (`0` destructive mutations).
- **Credential Redaction:** Across all VAmPI FELIX output files (`assessment_report.json`, `.html`, `.sarif`, logs, and Phase 5 JSON files), `0` bearer tokens or passwords leaked (`user_a`, `user_b`, and `admin` JWTs appeared only in the external Python wrapper `run_meta.json` `args` record).
- **Lab Cleanup:** VAmPI process (`task-44857`) was stopped and `C:\SecurityLabs\vampi\database\database.db` was restored and verified (`SHA256=4599BBD4AF03491CDA7CA941B2AA28CD42836858BC6CB3478276C1ECC6DB02BD`).
