# FELIX PILOT CAMPAIGN — OPERATOR CHECKLIST TEMPLATE

> **TEMPLATE ONLY:** Copy into `test/evidence/phase10/pilot_campaigns/<CAMPAIGN_ID>/preflight/operator_checklist.md` before executing an authorized pilot. Never bypass a `STOP` item.

- [ ] **1. Signed Authorization Contract:** Owner signed `authorization_contract.json` (`confirmed: true`), named `authorizing_party`, `signed_by`, and `authorization_ref`.
- [ ] **2. Exact Scope & Exclusions:** `authorized_targets` (scheme + host + explicit port) and `excluded_paths` / `excluded_urls` match written approval.
- [ ] **3. Binary Integrity Verified:** `Get-FileHash .\felix.exe -Algorithm SHA256` matches release record; `.\felix.exe version` inspected.
- [ ] **4. Private Workspace Initialized:** Campaign directories created with private `0600`/`0700` ACLs.
- [ ] **5. Independent Pre-Scan Ground Truth Built:** `ground_truth.json` constructed from code/specs BEFORE any FELIX scan (`derived_from_scanner: false`, `established_at` in past UTC).
- [ ] **6. Ground-Truth SHA-256 Computed & Locked:** `.\felix.exe validate hash-gt --ground-truth ground_truth.json` pasted into `campaign_manifest.json`.
- [ ] **7. Isolated Test Identities Prepared:** Local private `roles.config.json` (real staging test tokens, never templates/prod secrets, `0600` ACLs, never committed).
- [ ] **8. Verify-Auth Gate Passed (`0` Requests):** `.\felix.exe validate verify-auth` exits `0`.
- [ ] **9. Pilot-Readiness Check Passed (`0` Requests):** `.\felix.exe validate pilot-readiness --json` reports `pilot_execution_status: "READY"` (checks `1..15` clear).
- [ ] **10. Active UTC Testing Window Confirmed:** Current UTC strictly within `[window_start, window_end]` with sufficient runtime buffer.
- [ ] **11. Rate Limits & Kill-Switch Verified:** `--rate-limit` set per SOW; owner technical emergency contact reachable.
- [ ] **12. Blind Assessment Executed:** `.\felix.exe assess --scope-manifest ... --roles-config ...` completed without ground-truth hints.
- [ ] **13. Authorization Summary Audited:** Confirmed `0` excluded routes or private/internal pivots requested.
- [ ] **14. Authorized Remediation & Live Retest (If Applicable):** Owner patched staging target; `felix.exe assess --retest` executed inside valid UTC window.
- [ ] **15. Statistical Evaluation & Cleanup:** `.\felix.exe validate evaluate` confirmed `blind_execution_verified: true`, `redaction_audit.clean: true`; live test tokens revoked and `roles.config.json` securely deleted.
