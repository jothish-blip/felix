# FELIX — PHASE 6: PERFORMANCE, RESOURCE & STABILITY REPORT

**Target Platform:** Windows 11 Home (`10.0.26300`, 64-bit, `15.79 GB` RAM, Go `1.27.0`)  
**Measurement Harness:** Python `subprocess` wrapper polling Windows `GetProcessMemoryInfo().PeakWorkingSetSize` every `100ms`, recording wall-clock runtime, FELIX internal `duration_ms`, generated output artifact sizes, exit codes, and error logs across **`20` live CLI runs** (`8` VAmPI `V1`–`V7`, `6` Juice Shop `J1`–`J6`, `6` crAPI `C1`–`C6`).

---

## 1. Unified Performance & Resource Matrix (`20` Campaigns)

| Target | Run ID | Profile / Flags | Exit | Wall (s) | FELIX (ms) | Peak RAM (MB) | Discovery Reqs | Authz Reqs | Discovered Pages / Confirmed EPs / Candidates / JS Bundles | HTML Bytes |
|---|---|---|---:|---:|---:|---:|---:|---:|---|---:|
| **VAmPI** | `v1_unauth_full` | `full` unauth | `0` | `0.412` | `217` | `27.42` | `1` | `4` | `0 / 1 / 0 / 0` | `84,269` |
| **VAmPI** | `v2a_usera_full` | `full` `--auth user_a` | `0` | `0.412` | `213` | `27.45` | `2` | `4` | `0 / 2 / 0 / 0` | `84,263` |
| **VAmPI** | `v2b_userb_full` | `full` `--auth user_b` | `0` | `0.415` | `220` | `28.53` | `2` | `4` | `0 / 2 / 0 / 0` | `84,263` |
| **VAmPI** | `v3_multirole_ro` | `api` `--roles-config` | `0` | `0.314` | `75` | `26.76` | `4` | `4` | `0 / 4 / 0 / 0` | `84,172` |
| **VAmPI** | `v4_multirole_mut` | `full` `--roles-config` mutating | `0` | `0.409` | `245` | `28.75` | `4` | `4` | `0 / 4 / 0 / 0` | `84,181` |
| **VAmPI** | `v5_safe_neg` | `full` `--safe` | `0` | `0.209` | `17` | `26.60` | `1` | `0` | `0 / 1 / 0 / 0` | `81,702` |
| **VAmPI** | `v6_ui_multirole_mut` | `full` mutating `/ui/` | `0` | `3.424` | `3265` | `63.43` | `12` | `4` | `4 / 4 / 0 / 8` | `84,213` |
| **VAmPI** | `v7_retest` | `--retest v4` | `0` | `0.109` | — | `22.80` | — | — | `4 retested` (`0.109s`) | — |
| **Juice Shop** | `j1_unauth_full` | `full` unauth | `1` | `17.393` | `15978` | `84.05` | `4` | `10` | `1 / 1 / 6 / 3` | `193,549` |
| **Juice Shop** | `j2_usera_full` | `full` `--auth user_a` | `1` | `26.347` | `25184` | `85.40` | `8` | `16` | `2 / 2 / 12 / 6` | `193,545` |
| **Juice Shop** | `j3_multirole_ro` | `api` `--roles-config` | `0` | `3.494` | `3110` | `111.35` | `16` | `28` | `4 / 4 / 24 / 12` | `94,090` |
| **Juice Shop** | `j4_multirole_mut` | `full` `--roles-config` mutating | `1` | `18.794` | `17782` | `102.41` | `16` | `28` | `4 / 4 / 24 / 12` | `212,705` |
| **Juice Shop** | `j5_safe_neg` | `full` `--safe` | `0` | `1.919` | `1714` | `83.58` | `4` | `0` | `1 / 1 / 6 / 3` | `72,299` |
| **Juice Shop** | `j6_retest` | `--retest j4` | `0` | `0.713` | — | `33.94` | — | — | `26 retested` (`0.713s`) | — |
| **crAPI** | `c1_unauth_full` | `full` unauth | `1` | `20.236` | `19786` | `70.72` | `2` | `4` | `1 / 1 / 0 / 1` | `128,975` |
| **crAPI** | `c2_usera_full` | `full` `--auth user_a` | `1` | `29.294` | `28508` | `88.79` | `4` | `4` | `2 / 2 / 0 / 2` | `128,969` |
| **crAPI** | `c3_multirole_ro` | `api` `--roles-config` | `0` | `2.735` | `2459` | `81.98` | `6` | `4` | `3 / 3 / 0 / 3` | `84,267` |
| **crAPI** | `c4_multirole_mut` | `full` `--roles-config` mutating | `1` | `27.919` | `27426` | `89.54` | `6` | `4` | `3 / 3 / 0 / 3` | `128,980` |
| **crAPI** | `c5_safe_neg` | `full` `--safe` | `0` | `2.042` | `1824` | `77.04` | `2` | `0` | `1 / 1 / 0 / 1` | `81,704` |
| **crAPI** | `c6_retest` | `--retest c4` | `0` | `0.213` | — | `26.87` | — | — | `13 retested` (`0.213s`) | — |

*(Every active/safe assessment produced all `11` standard output files when `--json --verbose` was passed: `assessment_report.{json,html,sarif}`, `discovery_summary.json`, `authorization_summary.json`, `coverage_matrix.json`, `investigated_findings.json`, `attack_chains.json`, `remediation_roadmap.json`, plus harness logs `stdout.log`, `stderr.log`, `run_meta.json`; retest produced `retest_report.json`. In `v6_ui_multirole_mut`, an extra file brought total dir entries to `12`.)*

---

## 2. Operational Stability & Resource Behavior

1. **Zero Crashes, Panics, or Hangs (`20/20` clean exits):**
   - `11/11` non-retest assessments without Critical/High findings (`v1`–`v6`, `j3`, `j5`, `c3`, `c5`) exited with `0`.
   - `6/6` assessments reporting Critical/High findings (`j1`, `j2`, `j4`, `c1`, `c2`, `c4`) exited cleanly with CI/CD threshold code `1`.
   - `3/3` `--retest` runs (`v7`, `j6`, `c6`) exited with `0` in under `0.8s` (`14` total `exit=0` + `6` total `exit=1` = `20`).
   - CLI validation check (omitting `--output` during harness check) exited deterministically with code `2`.
2. **Bounded Memory Footprint:**
   - Lightweight JSON API scans (`v1`–`v5`) peaked at **`26.60–28.75 MB`** RSS.
   - SPA targets fetching multi-megabyte Webpack/Angular bundles (`main.js` on Juice Shop, `1.65 MB` `main.8c78208c.js` on crAPI) peaked cleanly at **`70.72–111.35 MB`** RSS (overall Phase 6 peak: **`111.35 MB`** during `j3_multirole_ro`).
3. **Timing Profile Drivers:**
   - Comparing `full` active scans (`17.4s–29.3s` on Juice Shop/crAPI) vs `--safe` (`1.92s–2.04s`) and `--profile api` (`2.74s–3.49s`) shows ~`15s–27s` of execution time in `full` SPA runs comes from active `webvuln` HTTP payload fan-out (`30s` per-request timeout bound, `5` concurrent workers).
   - Multi-role crawls (`4` identities on Juice Shop) cleanly scaled bundle & page requests proportionally (`16` discovery requests vs `4` unauth) without exponential blowup or infinite SPA pagination loops.
   - Cross-VM localhost forwarding overhead on crAPI (`kali-linux-2026.2-virtualbox-amd64` via `127.0.0.1:8888`) added negligible latency compared to native Windows Node.js (`27.9s` vs `18.8s` for `c4` vs `j4`).
4. **Asset Coverage (`coverage_matrix.json`):**
   - Overall metric ranged `21.9%–43.8%` across targets; `coverage_matrix.json` tracked `8`–`14` assets on VAmPI, `56` on Juice Shop, and `10` on crAPI, accurately reflecting `1` tested root/base host asset vs unprobed JS/static/inferred assets.
5. **Credential Hygiene Under Load:**
   - Automated check across all **`196` FELIX-generated output artifacts** (`20` runs excluding test-harness `run_meta.json`) confirmed **`0` raw bearer token leaks, `0` test password leaks, and `0` `.env` credential leaks** (including redaction of `?key=[REDACTED]` and `crapi /.env` secret redaction).
