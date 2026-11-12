# FELIX PHASE 9 — FINAL TECHNICAL REPORT

**Project:** FELIX — Security Assessment & Vulnerability Intelligence Platform  
**Repository:** `C:\Jothish\felix` (`main`, baseline `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9`)  
**Platform:** Windows 11 (`go version go1.27.0 windows/amd64`, `CGO_ENABLED=0`)  
**Phase Status:** **HARDENING, SUPPLY-CHAIN SBOM & PACKAGING AUDIT COMPLETE**  
**Release Gate Classification:** **`CONDITIONALLY READY FOR CONTROLLED PILOT`**  
**Date:** 2026-11-12

> [!IMPORTANT]
> This report establishes FELIX's security hardening, operational safety, Windows build/packaging integrity, and dependency supply-chain readiness. It does **not** claim universal detection accuracy, commercial production code-signing certification, or live external accuracy verification (no third-party target was scanned during Phase 9).

---

## 1. Executive Technical Summary

Phase 9 audited FELIX's complete runtime, authentication/scope enforcement, network/SSRF boundaries, TLS configuration, signal/window cancellation, file permissions, evaluator invariants, supply-chain dependencies, and Windows release packaging. Seven concrete security and integrity defects uncovered during the audit were remediated and covered by new regression tests, followed by full workspace verification (`49/49` tested Go packages passing, `0` failures) and a trimmed, leak-inspected Windows binary build (`felix.exe` and `bin/felix.exe`).

All historical Phase 0–8 reports, campaign artifacts, and prior Phase 9.1–9.4 milestone proofs under [test/evidence/phase9/](file:///C:/Jothish/felix/test/evidence/phase9) remain completely intact.

---

## 2. Phase 9 Security Hardening & Engineering Fixes Implemented

### 2.1 TLS Certificate Verification Fail-Closed by Default
During the Phase 9 audit, four HTTP client/transport paths and one headless browser default were found to skip TLS verification unconditionally (`InsecureSkipVerify: true`):
1. [pkg/auth/transport.go](file:///C:/Jothish/felix/pkg/auth/transport.go): Added `InsecureSkipVerify bool` to `AuthenticatedTransportOptions` and `IdentityManagerOptions` (default `false`), enforcing `&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify}`. Hardened `IdentityManager.BuildClient`'s `CheckRedirect` callback to reject non-HTTP(S) schemes and embedded URL userinfo (`req.URL.User != nil`) alongside hop limits (`10`), `ScopeAllowed`, `ProhibitedIPReason`, and cross-origin / HTTPS-to-HTTP downgrade credential header stripping (`Authorization`, `Proxy-Authorization`, `Cookie`).
2. [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go): Added opt-in `--insecure` (`AssessOptions.InsecureSkipVerify`, default `false`), propagated it to `auth.IdentityManagerOptions` in both `runAssess` and `runRetest`, and replaced the hardcoded `InsecureSkipVerify: true` on `runRetest`'s fallback transport with `MinVersion: tls.VersionTLS12`, `InsecureSkipVerify: opts.InsecureSkipVerify`, `ScopeAllowed: scopeAllowed` in `idMgr`, and `buildSafeRedirectPolicy`.
3. [cmd/felix/recon_cmd.go](file:///C:/Jothish/felix/cmd/felix/recon_cmd.go) and [cmd/felix/secrets_cmd.go](file:///C:/Jothish/felix/cmd/felix/secrets_cmd.go): Replaced unconditional `InsecureSkipVerify: true` with `MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify` (`--insecure` flag, default `false`) and attached `buildSafeRedirectPolicy`.
4. [pkg/crawler/browser/launcher.go](file:///C:/Jothish/felix/pkg/crawler/browser/launcher.go): Changed `DefaultConfig().IgnoreCertErrors` from `true` to `false`.

### 2.2 Scope Normalization, Port/Scheme Enforcement & SSRF IPv6/Transition Hardening
1. **Path Normalization Against Exclusion Bypasses ([pkg/assessment/scope.go](file:///C:/Jothish/felix/pkg/assessment/scope.go)):** Added `normalizeScopePath` (up to two `url.PathUnescape` passes, `\` to `/` conversion, `//` collapse, `path.Clean`) and enforced normalized matching across `IsExcluded` (`PATH_PREFIX`, `EXACT_URL`, fallback) so encoded or traversal variants (`/%61dmin/reset`, `/foo/../admin/reset`, `//admin//reset`, `\admin\reset`) cannot evade exclusions.
2. **Scheme/Port Discipline Across All `ScopeMode` Variants ([pkg/assessment/scope.go](file:///C:/Jothish/felix/pkg/assessment/scope.go) & [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go)):** Added `sameTargetOrigin` (scheme, hostname, `EffectivePort`) across `default:`, `same-origin`, `explicit_allowlist_with_exclusions`, and `explicit` branches (preventing Phase 8 manifest `"EXPLICIT_ALLOWLIST_WITH_EXCLUSIONS"` from hitting a port/scheme-agnostic default branch). Updated `buildAssessScopePolicy` to enforce `scopeValidator.IsAllowed` when `--scope` is unset, and scheme + contract authorization checks when `--scope` is set.
3. **Extended SSRF Transition/Reserved IPv4 & IPv6 Blocking ([pkg/crawler/safe_dialer.go](file:///C:/Jothish/felix/pkg/crawler/safe_dialer.go)):** Extended `ProhibitedIPReason` to unconditionally block NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), Teredo (`2001::/32`), 6to4 (`2002::/16`), IPv6 documentation (`2001:db8::/32`), discard (`100::/64`), and reserved/benchmark/documentation IPv4 CIDRs (`192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`), even when `--allow-loopback` or `--allow-private` is enabled.

### 2.3 Mid-Scan Authorization Window Expiry, Signal Cancellation & Fail-Closed Target Probing
1. `buildAssessScopePolicy` in [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go) now returns `contract.WindowEnd`.
2. `runAssess` and `runRetest` initialize `signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)` wrapped with `context.WithDeadline(..., windowEnd)` when `--scope-manifest` specifies `window_end`.
3. Added `windowGuardTransport` (`wrapWindowGuard`) wired onto both `httpClient.Transport` and `AssessmentRuntimeContext.ClientFor(...)`, enforcing `ctx.Err()` and `time.Now().UTC().Before(windowEnd)` on every outbound HTTP round-trip, alongside `ctx.Err()` checks between modules and retest findings.
4. Propagated `rt.ctx()` throughout assessment module HTTP/crawl calls in [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go) instead of `context.Background()`.
5. Changed initial target probe failure (`runAssess`) to fail closed (`return 2`) instead of ignoring network/TLS errors and emitting a clean report with exit code `0`.

### 2.4 Least-Privilege File Permissions & Atomic Writes
1. [pkg/config/config.go](file:///C:/Jothish/felix/pkg/config/config.go): Restricted `Save()` directory and file permissions from `0755`/`0644` to `0700`/`0600`.
2. [cmd/felix/assess_cmd.go](file:///C:/Jothish/felix/cmd/felix/assess_cmd.go), [cmd/felix/recon_cmd.go](file:///C:/Jothish/felix/cmd/felix/recon_cmd.go), and [cmd/felix/secrets_cmd.go](file:///C:/Jothish/felix/cmd/felix/secrets_cmd.go): Replaced `os.WriteFile(..., 0644)` and `os.MkdirAll(..., 0755)` with `0700` directories and atomic `writePrivateFile` (`0600` temp file + `Sync` + `Close` + `Rename`) across HTML/JSON/SARIF reports and auxiliary `coverage_matrix.json`, `discovery_summary.json`, `authorization_summary.json`, `remediation_roadmap.json`, `attack_chains.json`, `investigated_findings.json`, `retest_report.json`, recon, and secrets outputs.

### 2.5 Accuracy Evaluator Structural Guards (`pkg/validation/evaluator.go`)
1. `EvaluateAccuracy` in [pkg/validation/evaluator.go](file:///C:/Jothish/felix/pkg/validation/evaluator.go) now rejects empty or duplicate `GroundTruthEntry.ID`, invalid `ExpectedStatus`, empty or duplicate `RetestExpectedItem.FindingID`, and invalid `RetestExpectedItem.ExpectedAction` (must be `FIXED` or `STILL_PRESENT`).
2. Step-2 finding corroboration now requires BOTH `NormalizeVerificationStatus(f.Verification.Status) == VerificationVerified` AND `satisfiedTPIDs[entry.ID]` (established in Step 1), guaranteeing unverified candidate findings never receive `OutcomeTP` in `EvidenceComparison`.
3. `checkNegativeControlCoverage` only counts `DISCOVERY_OBSERVATION` as `SECURITY_HEADERS` `TN` when `manifest != nil` with a non-`custom` profile (or when explicit `SECURITY_HEADERS` results exist).

---

## 3. Build, Packaging, Sterile Execution & Supply-Chain Evidence

| Verification / Artifact | Observed Result | Reference |
| :--- | :--- | :--- |
| **`go build ./...`** | **PASS (`exit 0`)** | [phase9_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/phase9_verification_summary.json) |
| **`go vet ./...`** | **PASS (`exit 0`)** | [phase9_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/phase9_verification_summary.json) |
| **`go test -p 1 -count=1 ./...`** | **PASS (`exit 0`) — `49/49` tested packages `ok`, `0` failed**, `2` `[no test files]` (`felix/scratch`, `felix/test/lab/cmd/multiclass`) | [phase9_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/phase9_verification_summary.json) |
| **`go test -race ./pkg/validation`** | **NOT EXECUTABLE (`exit 2`)** — `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (no `gcc` on host) | [phase9_verification_summary.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/phase9_verification_summary.json) |
| **`go mod verify`** | **PASS** — `all modules verified` | [release_inspection.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/release_inspection.json) |
| **CycloneDX 1.5 SBOM** | **Generated (`39` direct & indirect Go module components)** via `go list -m -json all` | [felix_sbom_cyclonedx.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/felix_sbom_cyclonedx.json) |
| **Trimmed Windows Binary (`felix.exe`)** | `32,418,304` bytes, `sha256:13f23c11213470ba9ff2d80f246ed617a8989f8f2883109adc2892057f3617e7`, `-trimpath=true` (`C:\Jothish` = `false`, `Users\LENOVO` = `false`, PGP/RSA private keys = `false`) | [release_inspection.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/release_inspection.json), [binary_buildinfo.txt](file:///C:/Jothish/felix/test/evidence/phase9/audit/binary_buildinfo.txt) |
| **Sterile Windows Execution** | Isolated temp dir + minimal `PATH=C:\Windows\System32;C:\Windows`: `version` (`exit 0`), `doctor` (`exit 0`, all 8 runtime checks PASS, Authenticode `[INFO] Unsigned`), `assess --help` (`exit 0`), `validate --help` (`exit 0`) | [release_inspection.json](file:///C:/Jothish/felix/test/evidence/phase9/audit/release_inspection.json) |

*(Note: During intermediate Phase 9 verification, stamping `-X main.Version=2.0.0` onto the repository `felix.exe` caused `felix/test` integration tests `TestCLI_Version` and `TestCLI_VersionVariants` to fail because [test/cli_test.go](file:///C:/Jothish/felix/test/cli_test.go) asserts `"1.0.0"`. Rebuilding `felix.exe` and `bin/felix.exe` with `Version=1.0.0` restored full `49/49` suite pass status.)*

---

## 4. Regression & Adversarial Tests Added in Phase 9

- [pkg/assessment/phase9_scope_test.go](file:///C:/Jothish/felix/pkg/assessment/phase9_scope_test.go): `TestPhase9_ScopeValidator_NormalizationAndSchemePort`
- [pkg/crawler/phase9_ssrf_test.go](file:///C:/Jothish/felix/pkg/crawler/phase9_ssrf_test.go): `TestPhase9_ProhibitedIPReason_ExtendedTransitionAndReservedRanges`
- [pkg/crawler/browser/phase9_tls_test.go](file:///C:/Jothish/felix/pkg/crawler/browser/phase9_tls_test.go): `TestPhase9_DefaultConfig_VerifiesTLSCerts`
- [pkg/auth/phase9_tls_test.go](file:///C:/Jothish/felix/pkg/auth/phase9_tls_test.go): `TestPhase9_DefaultTLSVerification_Enforced`
- [pkg/validation/evaluator_test.go](file:///C:/Jothish/felix/pkg/validation/evaluator_test.go): `TestPhase9_Evaluator_ValidationGuards_And_NoUnverifiedCorroboration`
- [cmd/felix/security_phase9_test.go](file:///C:/Jothish/felix/cmd/felix/security_phase9_test.go): `TestPhase9_ScopePolicy_PathNormalizationBypassBlocked`, `TestPhase9_MidScanAuthorizationWindowExpiry_HaltsRequests`, `TestPhase9_TLSVerificationDefault_RejectsUntrustedCertWithoutInsecureFlag`, `TestPhase9_HTMLReport_XSSEscaping`

All historical Phase 9.1–9.4 milestone proofs remain preserved under [test/evidence/phase9/](file:///C:/Jothish/felix/test/evidence/phase9) (`9.1_attestation_letter_signature_proof.json` through `9.4_preflight_guardrail_safety_proof.json`).
