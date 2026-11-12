# FELIX — PHASE 6: FALSE POSITIVE & FALSE NEGATIVE ANALYSIS REPORT

This report documents every observed False Positive (FP) and False Negative (FN) defect from FELIX Phase 6 validation, backed by reproducible runtime logs, HTTP response bodies, and exact FELIX code locations inspected during diagnosis.

---

## 1. False Positives (`32` Critical Alerts Across Juice Shop & crAPI)

### Defect FP-01: Invariant Response-Substring Matching Causes `32` False `CRITICAL` `WV-CMDI` Alerts
- **Observed Impact:**
  - **OWASP Juice Shop (`J1`, `J2`, `J4`):** `24` `CRITICAL` alerts (`Remote OS Command Injection via Parameter {cmd, command, exec, run, ping, host, ip, username} on {/api/Challenges, /api/Hints, /polyfills.js}`).
  - **OWASP crAPI (`C1`, `C2`, `C4`):** `8` `CRITICAL` alerts (`Remote OS Command Injection via Parameter {cmd, command, exec, run, ping, host, ip, username} on /`).
  - **VAmPI (`V1`–`V7`):** `0` CMDI FPs (because `GET /` JSON `{"help": ...}` contained none of the indicator strings).
- **Exact Root Cause (`pkg/webvuln/engine.go:788`):**
  The `webvuln` CMDI check sends `GET <endpoint>?<param>=whoami` across `8` candidate parameter names and matches response bodies against static OS/user substrings (`"root"`, `"system"`, `"windows"`, `"uid="`, `"www-data"`, etc.) **without diffing against an unparameterized baseline response**:
  - Juice Shop `GET /api/Challenges` natively contains the words `"system"` and `"windows"` inside challenge titles/descriptions.
  - Juice Shop `GET /api/Hints` natively contains `"system"`.
  - Juice Shop `GET /polyfills.js` and crAPI `GET /` (`<div id="root"></div>`) natively contain `"root"`.
- **Contradictory Evidence Emitted:**
  - `evidence.observation` erroneously writes `"Confirmed OS command execution output in response via parameter '<p>' on <path> (whoami probe returned active account)"` and `top_priorities` assigns `score: 40/40` (`VERIFIED`).
  - Yet Phase 5 (`investigated_findings.json` and `findings[].verification.status`) classifies all `32` as `"NOT TESTED"` (`UNTESTED_CATEGORY_PROCEDURE`).
- **Recommended Engineering Fix (Phase 7/remediation candidate — not modified in Phase 6):**
  1. Require differential baseline verification: any indicator token already present in the baseline response (same endpoint with benign parameter or no parameter) must be excluded.
  2. Never attach arbitrary query fuzzing (`?cmd=whoami`) to static JS bundle paths (e.g., `/polyfills.js`).
  3. Require command-execution-specific delimiters or randomized canary reflection (not plain English words like `"system"`, `"windows"`, `"root"` inside JSON/HTML/JS).

---

## 2. False Negatives & Discovery Blind Spots (`24` Missed Vulnerabilities Across `3` Targets)

### Defect FN-01: Fetched OpenAPI 3.0.1 Spec Not Ingested Into Endpoint/Authz Discovery (`VAmPI`)
- **Evidence:** In VAmPI `task-44857.log` (`V1`–`V4`), FELIX explicitly requested `GET /openapi.json` and received `HTTP 200` (`12,613` bytes, valid OpenAPI 3.0.1 YAML-derived JSON defining `/users/v1/_debug`, `/books/v1/{book}`, `/users/v1/register`, `/users/v1/{username}/password`, etc.).
- **Failure:** `discovery_summary.json` recorded only `GET /` (`total_endpoint_candidates: 0`), `apisec` emitted `0` findings, and `authorization_summary.json` recorded `objects_discovered: 0`, `functions_discovered: 0`, `properties_discovered: 0`, `requests_sent: 4`.
- **Consequence:** `6` executable VAmPI vulnerabilities (`VAMPI-GT-01`, `02`, `04`, `05`, `08`, `09`) were missed (`0%` API/Authz recall on VAmPI).

### Defect FN-02: Partial Angular JS Route Extraction Misses `/rest/*` & Utility Paths (`Juice Shop`)
- **Evidence:** FELIX crawled `main.js`, `polyfills.js`, `scripts.js`, `styles.css` (`12` bundle hits across identities) and successfully extracted `6` `/api/*` paths (`/api/Cards`, `/api/Challenges`, `/api/Challenges?key=[REDACTED]`, `/api/Deliverys`, `/api/Feedbacks`, `/api/Hints`).
- **Failure:** Missed `/rest/products/search`, `/rest/user/login`, `/rest/basket/{id}`, `/rest/user/whoami`, `/profile/image/url`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, `/api-docs`, and `/redirect`.
- **Consequence:** `8` executable Juice Shop vulnerabilities (`JS-GT-01`..`08`) were missed. (Even `/api/Challenges/{id}`, which generated `30` BOLA probes in `J3`/`J4`, produced `30/30` `INCONCLUSIVE` because ownership could not be inferred for public challenge objects.)

### Defect FN-03: React JS Route Objects Without Leading Slashes Yield `0` Candidates (`crAPI`)
- **Evidence:** FELIX fetched `/static/js/main.8c78208c.js` (`1,655,900` bytes) across `ANONYMOUS`, `USER_A`, and `USER_B`, yet `discovery_summary.json` reported `total_endpoint_candidates: 0`.
- **Root Cause Observed Directly in `main.8c78208c.js`:** crAPI defines `42` routes without leading `/` inside a constant map (`LOGIN:"api/auth/login"`, `REFRESH_LOCATION:"api/v2/vehicle/<carId>/location"`, `CONTACT_MECHANIC:"api/merchant/contact_mechanic"`, `BUY_PRODUCT:"api/shop/orders"`, etc.) prefixed dynamically with `"identity/"`, `"workshop/"`, `"community/"`, `"chatbot/"`. Because FELIX's static bundle extractor matches only `/...` literals, it extracted `0` API candidates.
- **Consequence:** `10` OWASP API Top 10 ground-truth cases (`CRAPI-GT-01`..`10`) were never reached.

### Defect FN-04: Non-Root Target Path Duplication (`V6`: `/ui/` -> `/ui/ui/*`)
- **Evidence:** When running `V6` against `http://127.0.0.1:5000/ui/` (Connexion Swagger UI), VAmPI's access log (`task-44857.log:517-755`) recorded FELIX requesting `/ui/ui/*` and `/ui/openapi.json` -> `HTTP 404`, failing to normalize non-root base paths against root-relative links or root OpenAPI specs.

### Defect FN-05: Retest Engine Unable to Re-Validate Non-Proof Categories (`V7`, `J6`, `C6`)
- **Evidence:** Across `V7` (`4` findings), `J6` (`26` findings), and `C6` (`13` findings), **`43/43` (`100%`)** retested findings returned `original_status: "NOT TESTED"` -> `RETEST INCONCLUSIVE` (`fixed_count: 0`, `still_present_count: 0`), preventing automated regression verification of header fixes, `/.env` fixes, or active findings.

### Defect FN-06: `summary` Counter Undercounts When `HDR-CSP` Merges `HDR-NOSNIFF`
- **Evidence:** On VAmPI (`V1`–`V6`) and crAPI (`C1`–`C5`), `HDR-CSP` recorded `duplicate_finding_ids: "HDR-NOSNIFF-..."`, causing `summary.low_count` to drop from `2` to `1` (`summary.total_findings` = `3` on VAmPI, `12` on crAPI) even though `findings[]`, `assessment_report.sarif`, and `remediation_roadmap.json` all contain `4` and `13` items respectively.
