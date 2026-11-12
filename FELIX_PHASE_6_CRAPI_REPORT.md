# FELIX — PHASE 6: OWASP crAPI VALIDATION REPORT

**Target Application:** OWASP crAPI `v1.1.5` (`C:\SecurityLabs\crapi`, commit `b5fc307`)  
**Endpoint:** `http://127.0.0.1:8888` (OpenResty `1.27.1.2` web gateway) & `http://127.0.0.1:8025` (MailHog)  
**Infrastructure:** Docker Compose (`docker-compose.yml` + `docker-compose.minimal.yml`, 10 containers up/healthy) inside local VirtualBox VM `kali-linux-2026.2-virtualbox-amd64` with `127.0.0.1`-only NAT port forwarding  
**FELIX Binary Tested:** Isolated build from `C:\Jothish\felix` `HEAD` (`4fc8c8e`)  
**Campaign Scope:** Campaigns `C1`–`C6` (`c1_unauth_full` through `c6_retest`)  
**Testing Stance:** Strictly blind CLI execution targeting only `http://127.0.0.1:8888`.

---

## 1. Deployment & Pre-Scan Verification

1. **Container Topology Running During Tests:** `crapi-web`, `crapi-identity`, `crapi-community`, `crapi-workshop`, `crapi-chatbot`, `api.mypremiumdealership.com`, `postgresdb`, `mongodb`, `mailhog`, `chromadb`.
2. **Synthetic Identities & Owned Objects Seeded:**
   - `user_a`: `p6usera@example.com` (`id=12`, `"role": "user"` / `ROLE_USER` via public signup), vehicle `VIN=GB4GXUG76PAHDK164` (`uuid=426c6292-10c4-43cf-8608-3582b5d05190`, `BMW 5 Series`, added using MailHog pincode `9415`), community post `z3JduLqnakdurqdxc2RUp9`, shop order `id=23`.
   - `user_b`: `p6userb@example.com` (`id=13`, `"role": "user"` / `ROLE_USER` via public signup), vehicle `VIN=65RPT0WZL9JEX4911` (`uuid=c9bf5007-1e3f-4e29-b5ac-8e40ba02dbac`, `Hyundai Creta`, pincode `4054`), community post `uNg4WXjV7sGvSfPBfRCyUd`, shop order `id=24`.
   - **Admin Persona Constraint:** Public crAPI signup issues standard `ROLE_USER` JWT tokens only (`RS256`); therefore `crapi_roles.json` supplied distinct `user_a` and `user_b` identities without an `admin` credential, leaving Scenario D admin-versus-user BFLA comparisons on crAPI explicitly marked `PARTIAL` / `NOT_CONFIGURED` for `ADMIN`.
3. **Live Ground-Truth Pre-Checks:**
   - `GET /identity/api/v2/vehicle/c9bf5007-1e3f-4e29-b5ac-8e40ba02dbac/location` as `user_a` -> `HTTP 200` returning `user_b`'s GPS coordinates (`CRAPI-GT-01` live BOLA confirmed; same request unauthenticated -> `401`).
   - `GET /community/api/v2/community/posts/recent` -> `HTTP 200` exposing author emails (`CRAPI-GT-03` confirmed).
   - `GET /.well-known/jwks.json` -> `HTTP 200` (`CRAPI-GT-09`).
   - `GET /workshop/api/management/users/all` unauthenticated -> `HTTP 401` (`JWT Token required!`); `GET /workshop/api/shop/products` unauthenticated -> `HTTP 401`; invalid login -> `HTTP 401`.
   - `GET /.env` on `127.0.0.1:8888` -> **`HTTP 200 application/octet-stream` (`201` bytes)** exposing `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `SERVER_PORT`, `MONGO_DB_*`! (`GET /.git/config` -> `404 Not Found`.)
   - `GET /` headers: `Server: openresty/1.27.1.2`, `Content-Type: text/html`, `Content-Length: 1207`; absent `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy`.

---

## 2. Campaign Execution Matrix (`C1`–`C6`)

| Campaign | Profile / Mode | Exit | Wall Time (s) | FELIX Dur (ms) | Peak RAM (MB) | `findings[]` Len (`summary.total`) | Risk Score / Level | Authz Status |
|---|---|---:|---:|---:|---:|---|---|---|
| `C1` (`c1_unauth_full`) | `full`, anonymous | `1` | `20.236` | `19786` | `70.72` | `13` (`12`) | `35 / LOW` | `NOT_CONFIGURED` |
| `C2` (`c2_usera_full`) | `full`, `--auth` (`user_a`) | `1` | `29.294` | `28508` | `88.79` | `13` (`12`) | `35 / LOW` | `PARTIAL` |
| `C3` (`c3_multirole_ro`) | `api`, `--roles-config` (RO) | `0` | `2.735` | `2459` | `81.98` | `4` (`3`) | `7 / INFORMATIONAL` | `PARTIAL` (`NO_ADMIN`) |
| `C4` (`c4_multirole_mut`) | `full`, `--roles-config`, mutating | `1` | `27.919` | `27426` | `89.54` | `13` (`12`) | `35 / LOW` | `PARTIAL` (`NO_ADMIN`) |
| `C5` (`c5_safe_neg`) | `full`, `--safe` | `0` | `2.042` | `1824` | `77.04` | `4` (`3`) | `7 / INFORMATIONAL` | `NOT_CONFIGURED` |
| `C6` (`c6_retest`) | `--retest c4.../assessment_report.json` | `0` | `0.213` | — | `26.87` | — | — | `13/13 INCONCLUSIVE` |

---

## 3. Observed Results: True Positives, False Positives & False Negatives

### 3.1 Genuine Findings (True Positives — 4 Vulnerabilities + 1 Discovery Info)
In `C1`, `C2`, and `C4`:
1. **`HIGH` — `Sensitive Configuration Disclosure (Synthetic Fixture: /.env)` (`WV-INFODISC`):** Genuine True Positive verified directly against `crapi-web` OpenResty serving `/ .env` (`201` bytes, `DB_NAME=crapi`, `DB_USER=crapi`, `DB_PASSWORD=crapi`, `MONGO_DB_*`). Crucially, FELIX redacted all credential values from reports (`"all secrets redacted"`), with zero `DB_PASSWORD=crapi` leakage verified across all output artifacts. (`/.git/config` returning `404` was not falsely reported.)
2. **`Medium` — `Missing Content-Security-Policy (CSP)`:** Genuine True Positive verified against live headers.
3. **`Low` — `Missing Anti-Clickjacking Header (X-Frame-Options)`:** Genuine True Positive.
4. **`Low` — `Missing or Misconfigured X-Content-Type-Options`:** Genuine True Positive.
5. **`Info` — `Discovered 2 attack surface endpoints on 127.0.0.1`:** Informational discovery observation (`0/40` score).

*(Same deduplication/accounting anomaly as VAmPI: `HDR-CSP` absorbed `HDR-NOSNIFF` in `summary`, producing `total_findings: 12`, `low_count: 1` while keeping all `13` items inside `findings[]`, SARIF, and remediation tasks. Also note the `/.env` finding carried `"NOT TESTED"` inside `findings[]` and `investigated_findings.json` even though `top_priorities` rated it `VERIFIED` and `score: 40`.)*

### 3.2 False Positives — `8 CRITICAL` OS Command Injection Findings on `/`
In `C1`, `C2`, and `C4`, FELIX emitted **`8 CRITICAL` `WV-CMDI / OS Command Injection` false positives** on `GET /` (`?cmd=`, `?command=`, `?exec=`, `?run=`, `?ping=`, `?host=`, `?ip=`, `?username=`).
- **Root Cause Verified Directly:** `http://127.0.0.1:8888/` returns React `index.html` (`1,207` bytes) containing `<div id="root"></div>`. That static `"root"` substring satisfied FELIX's invariant substring matcher on `/?<param>=whoami`, identical in mechanism to the `24` Juice Shop FPs.
- In `--safe` mode (`C5`) and `--profile api` (`C3`), active web probing did not trigger these `8` FPs (`0` FPs).

### 3.3 False Negatives — Root Cause in React SPA Bundle URL Construction
FELIX missed all API-layer OWASP API Top 10 vulnerabilities in crAPI (`CRAPI-GT-01` vehicle GPS BOLA, `CRAPI-GT-02` mechanic report BOLA, `CRAPI-GT-03` community PII leak, `CRAPI-GT-04` video `conversion_params`/BOPLA, `CRAPI-GT-05` admin delete BFLA, `CRAPI-GT-06` negative order quantity, `CRAPI-GT-07` mechanic SSRF, `CRAPI-GT-08` NoSQLi coupon, `CRAPI-GT-09` JWKS/JWT weaknesses, `CRAPI-GT-10` management endpoint).

**Verified Root Cause in `/static/js/main.8c78208c.js` (`1,655,900` bytes):**
1. FELIX crawled `/`, `manifest.json`, `/static/css/main.dd33429d.css`, and `/static/js/main.8c78208c.js` (`total_pages_discovered: 3`, `total_javascript_bundles: 3`, `total_static_assets: 9` across 3 identities in `C4`).
2. However, `discovery_summary.json` reported **`total_endpoint_candidates: 0`** and crAPI exposes no OpenAPI spec at `/openapi.json`, `/api-docs`, or `/swagger-ui.html` (all `404`).
3. Direct inspection of `main.8c78208c.js` revealed crAPI stores all `42` API endpoints as **un-prefixed relative strings without leading slashes**, joined at runtime to service prefix constants:
   ```js
   og="identity/", ig="workshop/", ag="chatbot/", lg="community/",
   sg={LOGIN:"api/auth/login", GET_VEHICLES:"api/v2/vehicle/vehicles",
       REFRESH_LOCATION:"api/v2/vehicle/<carId>/location", ...}
   ```
   Because FELIX's regex extractor requires paths beginning with `/`, zero endpoints were extracted from the `1.65 MB` React bundle. Consequently, `authorization_summary.json` recorded `endpoints_observed: 4`, `objects_discovered: 0`, `functions_discovered: 0`, `properties_discovered: 0`, and `total_checks_executed: 0`.

---

## 4. Cleanup Verification

After completing `C1`–`C6`, all crAPI containers (`10` services) were torn down via `docker compose -f docker-compose.yml -f docker-compose.minimal.yml down`, both temporary `127.0.0.1` NAT forwarding rules (`crapi-web`, `crapi-mailhog`) were removed, `kali-linux-2026.2-virtualbox-amd64` was cleanly powered off (`VMState="poweroff"`), and ports `8888`/`8025` were verified closed on the Windows host. Zero user JWTs, passwords, or `.env` database credentials leaked into any FELIX output artifact (`0` leaks across all checked files).
