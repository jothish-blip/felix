# FELIX PHASE 7 — INITIAL ACCURACY AUDIT

**Repository:** `C:\Jothish\felix`  
**Baseline Commit:** `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9` (`main`)  
**Environment:** Windows 11, Go `go1.27.0 windows/amd64`  
**Audit Date:** 2026-11-12  

---

## 1. Executive Audit Summary

Following Phase 6 realistic application validation against local OWASP VAmPI, OWASP Juice Shop (`v20.2.0`), and OWASP crAPI (`v1.1.5`), a source-level accuracy audit was performed across the FELIX assessment pipeline prior to writing any code fixes.

The audit confirmed **every major Phase 6 accuracy failure stems from concrete, reproducible code defects** rather than target flakiness:

1. **P0-1 (CMDI False Positives & Loopback Fixture Confusion):** `pkg/webvuln/engine.go` promotes benign HTML/JS/JSON responses containing everyday words (`"lenovo"`, `"root"`, `"administrator"`, `"nt authority"`) to `VERIFIED` `CRITICAL` Command Injection without an unparameterized baseline request, without filtering `.js` bundles, and with blind default parameter guessing (`?username=whoami`, `?cmd=whoami`). Compounding this, `cmd/felix/assess_cmd.go:1637` sets `SyntheticFixture: rt.Opts.AllowLoopback`, misclassifying real local lab targets on `127.0.0.1` as synthetic fixtures.
2. **P0-2 (OpenAPI Ingestion Gap):** `cmd/felix/assess_authz.go` fetches `/openapi.json` (`200 OK`), records a single raw observation, and discards the specification without ever invoking `api.NewSpecParser().ParseSpecificationData(...)` (`pkg/api/spec_parser.go`), starving BOLA/BFLA/BOPLA/API/Web scanners of documented operations, parameters, and schemas.
3. **P0-3 (SPA & JS Route Extraction Failure):**
   - `pkg/crawler/js_parser.go` (`JSLexer.Tokenize`) lacks JavaScript RegExp literal scanning (`/pattern/flags`), causing `main.js` (Juice Shop) to fail at `Line 6552:6405: Unterminated string literal` and abort AST scanning.
   - `pkg/crawler/bundle_extractor.go` hardcodes `/api|v1|graphql|auth|webhook|oauth` in `rxDirectAPIPath`, `traverseAST`, and `inspectTemplateLiteral`, missing `/rest/*` (Juice Shop), `/identity/*`, `/workshop/*`, `/community/*`, `/chatbot/*` (crAPI), and Angular `this.http.get/post(...)` calls.
   - `collectConstants` only reads top-level `VariableDeclarationNode`s, missing function-scoped Webpack module prefix variables (`og="identity/"`) and object literal route maps (`sg={LOGIN:"api/auth/login", ...}`), while `NormalizeRouteCandidate` (`pkg/crawler/route_normalizer.go:98`) drops all routes lacking a leading `/`.
4. **P0-4 (Non-Root Base Path Failures):** `cmd/felix/assess_authz.go`, `pkg/webvuln/engine.go:buildEndpointURL`, and `cmd/felix/assess_cmd.go:1705` concatenate paths naively with `strings.TrimRight(base, "/")`, breaking root-relative specs (`/openapi.json` vs `/ui/openapi.json` 404) and route joining when `--target` includes a non-root path.
5. **P0-5 (Unified Status, Deduplication, Evidence & Commercial Report Contradictions):**
   - `pkg/investigation/live_session.go:178` writes `"CONFIRMED"` / `"POTENTIAL"` into `f.Verification.Status`, which `pkg/report/normalize.go:NormalizeVerificationStatus` fails to recognize and silently coerces to `"OBSERVED"`. Consequently `BuildCommercialReport` (`pkg/report/commercial_builder.go:1244`) sees zero verified/detected findings and emits `"No security findings were identified within the evaluated scope"` on reports containing `CRITICAL` findings.
   - `cmd/felix/assess_cmd.go` calls `report.BuildReport(...)` (deduplicating findings & computing `Summary` + `TopPriorities`) **before** `liveSession.EnrichReport(&rep)` replaces `rep.Findings` with un-deduplicated findings, producing `summary.total_findings` vs `len(findings)` mismatches (VAmPI: `3` vs `4`; crAPI: `12` vs `13`) and `NOT TESTED` vs `VERIFIED` status contradictions.
   - `pkg/correlation/fingerprint.go:extractHardeningDiscriminator` omits `f.Title` inspection, colliding `HDR-CSP` and `HDR-NOSNIFF` under the generic `"Missing Security Header"` category and silently dropping `HDR-NOSNIFF`.
   - `pkg/investigation/prover.go` passes `f.Target` (base URL) instead of `f.Endpoint` to `FormatSafeCurl(...)`, truncating reproduction URLs to the target root.
6. **P1-1 (Sibling `webvuln` False Positives):** `assessInfoDisclosure` reports `/.env` / `/.git/config` as `HIGH` `CANDIDATE` on any HTTP `200 OK` (triggering FPs on SPA catch-all `index.html` responses); `assessSSTI` and `assessNoSQLi` lack unparameterized baseline comparisons and static asset filtering.
7. **P1-2 (Retest Engine Deficiencies):** `pkg/investigation/prover.go` lacks safe proof handlers for CMDI, security headers, clickjacking, and info disclosure (`UNTESTED_CATEGORY_PROCEDURE`); `proveBOLA` and `proveBOPLA` trust stale `EvidenceDetails` metadata without executing live HTTP re-verification; `pkg/investigation/retest.go:64` can misclassify `UNTESTED_CATEGORY_PROCEDURE` as `FIX_DETECTED` for confirmed findings or fail closed to `RETEST_INCONCLUSIVE` on `NOT TESTED` strings.

---

## 2. Prioritized Defect Register (Initial Baseline)

| Defect ID | Severity | Package / File & Lines | Observed Symptom in Phase 6 | Root Cause in Source Code | Planned Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PH7-D01** | **P0** | `pkg/webvuln/engine.go:707-827, 2225-2233` | 32 CMDI `CRITICAL` FPs (24 Juice Shop, 8 crAPI) on `/polyfills.js`, `/rest/...`, `<div id="root">`, `"lenovo"` | Static substring check (`lenovo`, `root`, `administrator`, `nt authority`), no unparameterized baseline/negative diff, `.js` omitted from `isStaticAsset`, blind parameter guessing | Exclude `.js`/`.mjs`/`.map` static assets, require unparameterized baseline + negative control diff + real execution/command-output proof, downgrade ambiguous anomalies out of `VERIFIED` |
| **PH7-D02** | **P0** | `cmd/felix/assess_cmd.go:1637` | Live local targets (`127.0.0.1`) treated as mock fixtures | `SyntheticFixture: rt.Opts.AllowLoopback` conflates `--allow-loopback` network opt-in with mock fixture mode | Separate `SyntheticFixture: rt.Opts.SyntheticFixture` from `AllowLoopback` |
| **PH7-D03** | **P0** | `cmd/felix/assess_authz.go:628-664`, `pkg/api/spec_parser.go` | VAmPI `/openapi.json` (`200 OK`) yields 0 parsed endpoints for authz/api/web modules | Fetches raw bytes and stores 1 `OPENAPI_SPEC` observation; `api.NewSpecParser().ParseSpecificationData` never called in `assess` pipeline | Wire `api.NewSpecParser()` cleanly into discovery, authz candidate generation, `apisec`, and `webvuln`, handling `servers`/`basePath`, methods, params, malformed/error reporting |
| **PH7-D04** | **P0** | `pkg/crawler/js_parser.go:233-335` | `BUNDLE_WARNING: Unterminated string literal` on Juice Shop `main.js` line 6552 | `JSLexer.Tokenize` does not lex JS regex literals (`/pattern/flags`), so quotes inside `/.../` start phantom string literals until EOF | Add context-sensitive JS RegExp literal lexer support & bounded recovery if malformed string encountered |
| **PH7-D05** | **P0** | `pkg/crawler/bundle_extractor.go:34,288-566`, `pkg/crawler/route_normalizer.go:98-102` | Juice Shop `/rest/*` routes missed; crAPI `main.*.chunk.js` extracts `0` routes | `rxDirectAPIPath` & AST filters omit `/rest/`, Angular `this.http.*`, function-scoped vars, object route maps (`sg={...}`), relative routes (`api/auth/login`), prefix concat (`og + sg.LOGIN`) | Support `/rest/`, Angular/Axios/Fetch/XHR client patterns, scoped variable & object property maps, template/concat reconstruction, controlled relative route handling |
| **PH7-D06** | **P0** | `cmd/felix/assess_authz.go:617,633,689`, `pkg/webvuln/engine.go:2056`, `pkg/crawler/recursive.go:978` | `--target http://127.0.0.1:5000/ui/` fails `/openapi.json` (`404`) and misjoins routes | Naive `strings.TrimRight(base, "/") + path` ignores origin root vs non-root base path semantics | Introduce clean `url.URL` origin/base-path resolution for well-known specs, relative routes, and root-relative API paths |
| **PH7-D07** | **P0** | `pkg/report/normalize.go:205`, `pkg/report/commercial_builder.go:1244`, `pkg/investigation/live_session.go:178`, `pkg/report/summary.go:215` | `summary.total_findings` != `len(findings)`, `NOT TESTED` vs `VERIFIED` drift, `"No security findings..."` despite `CRITICAL` findings | Incompatible `ValidationStatus` (`CONFIRMED`/`POTENTIAL`) vs `VerificationStatus` (`VERIFIED`/`DETECTED`), stale `BuildReport` summary/top_priorities overwritten by `EnrichReport` | Unify canonical status mapping, rebuild `DeduplicateFindings`/`Prioritize`/`Summarize`/`RecalculateReportRisk`/`BuildCommercialReport` after enrichment & Phase 5 |
| **PH7-D08** | **P0** | `pkg/correlation/fingerprint.go:417-446` | `HDR-CSP` and `HDR-NOSNIFF` merged into 1 finding while summary kept earlier count | `extractHardeningDiscriminator` ignores `f.Title` / rule discriminator for `"Missing Security Header"` | Discriminate header findings by specific header name / title before fallback |
| **PH7-D09** | **P0** | `pkg/investigation/prover.go:51,128,548,825`, `pkg/investigation/types.go:262` | `safe_curl_command` points to base URL (`http://127.0.0.1:5000`) instead of vulnerable route | `FormatSafeCurl(f.Method, f.Target, ...)` uses `f.Target` instead of endpoint URL `f.Endpoint` | Resolve concrete affected endpoint URL (`f.Endpoint` resolved against `f.Target`) in all proof bundles & curl generation |
| **PH7-D10** | **P1** | `pkg/webvuln/engine.go:609,895,1052,1554` | `/.env` SPA `200 text/html` FP; `SSTI` / `NoSQLi` / `Traversal` lack baseline negative controls | `assessInfoDisclosure` flags HTTP 200 on `.env`/`.git/config` regardless of HTML SPA fallback; `assessSSTI`/`assessNoSQLi`/`assessPathTraversal` lack unparameterized baseline checks | Add SPA soft-404 / baseline HTML detection, require non-HTML or real secret-config indicators on `/.env`, add baseline negative checks & static-asset guards across webvuln checks |
| **PH7-D11** | **P1** | `pkg/investigation/prover.go`, `pkg/investigation/retest.go`, `cmd/felix/assess_cmd.go:runRetest` | Retest reports `RETEST INCONCLUSIVE` on 100% of Phase 6 findings, or false `FIX DETECTED` on BOLA/BOPLA/untested checks | Missing proof handlers for headers/info-disc/CMDI, `proveBOLA`/`proveBOPLA` return stale metadata without HTTP probe, `retest.go:64` equates non-confirmed/untested to fixed | Implement safe live HTTP re-verification across headers, clickjacking, info disclosure, CMDI, BOLA, BOPLA; distinguish `REMEDIATED` vs `STILL_VULNERABLE` vs `INCONCLUSIVE` strictly |
| **PH7-D12** | **P2** | `pkg/crawler/recursive.go:1087-1118` | `discovery_summary` inflates candidate/JS counts across multiple identities | `CrawlMultiIdentity` counts identical URLs per identity (`ANONYMOUS` + `USER_A` = 2x count) while deduplicating `AssetsForInventory` | Track both per-identity visibility matrix AND unique deduplicated counts accurately in summary |

---

## 3. Baseline Go Toolchain & Test Verification

Executed prior to any Phase 7 edits (`C:\Jothish\felix`):
- `go build ./...`: exit `0`
- `go vet ./...`: exit `0`
- `go test -p 1 -count=1 ./...`: exit `0` (`48` packages `ok`, `2` `[no test files]`: `felix/pkg/cli`, `felix/pkg/reporting`)
- `go test -race ./...`: exit `2` (`go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` — standard Windows non-CGO environment limitation)

---

## 4. Phase 7 Execution Sequence

1. **P0-1 (`PH7-D01`, `PH7-D02`, `PH7-D10`):** Harden `pkg/webvuln/engine.go` CMDI + sibling vulnerability checks (`SSTI`, `NoSQLi`, `Traversal`, `InfoDisclosure` SPA fallback) and separate `--synthetic-fixture` from `--allow-loopback`.
2. **P0-2 & P0-4 (`PH7-D03`, `PH7-D06`):** Centralize URL/base-path resolution and wire `pkg/api/spec_parser.go` OpenAPI 3.x / Swagger 2.0 ingestion into `assess_authz.go`, `assess_cmd.go`, `apisec`, and discovery.
3. **P0-3 (`PH7-D04`, `PH7-D05`, `PH7-D12`):** Upgrade `pkg/crawler` JS RegExp lexing, AST/constants/object-map extraction, Angular/React/Webpack `/rest/*` & relative prefix reconstruction, and summary uniqueness.
4. **P0-5 & P1 (`PH7-D07`, `PH7-D08`, `PH7-D09`, `PH7-D11`):** Unify finding-state/normalization/deduplication/commercial-report pipeline, fix `FormatSafeCurl` endpoint URLs, and repair `--retest` live proof verification & BOLA/BFLA/BOPLA accuracy.
5. **Re-Validation:** Full Go unit/integration regression + local Phase 6 VAmPI / Juice Shop / crAPI re-validation + Phase 7 accuracy metrics & closure reporting.
