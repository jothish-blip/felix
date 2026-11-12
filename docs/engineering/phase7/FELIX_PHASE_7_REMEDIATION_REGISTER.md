# FELIX PHASE 7 — REMEDIATION REGISTER

**Repository:** `C:\Jothish\felix`  
**Baseline Commit:** `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9` (`main`)  
**Completion Date:** 2026-11-12  

---

## 1. Defect Closure Matrix

| Defect ID | Priority | Root Cause Summary | Remediated File(s) | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **PH7-D01** | **P0** | CMDI bare keyword matching (`lenovo`, `root`, `administrator`), `.js` asset scanning, blind params, no baseline/negative diff | `pkg/webvuln/engine.go` (`isStaticAsset`, `assessCMDI`) | **FIXED** | `TestPhase7_CmdiFalsePositiveElimination_And_TruePositiveDifferential`; 0 CMDI FPs across VAmPI, Juice Shop, crAPI |
| **PH7-D02** | **P0** | `SyntheticFixture: rt.Opts.AllowLoopback` conflated loopback lab opt-in with mock fixture mode | `cmd/felix/assess_cmd.go` | **FIXED** | `--synthetic-fixture` & `--fixture-hosts` explicitly gated |
| **PH7-D03** | **P0** | `/openapi.json` fetched and discarded without calling `api.NewSpecParser().ParseSpecificationData` | `cmd/felix/assess_authz.go`, `pkg/apisec/engine.go` | **FIXED** | `TestPhase7_OpenAPIIngestionFromNonRootUI`, `TestPhase7_OpenAPIIgnoresSPAFallbackAndMalformedSpecSafely`; VAmPI endpoints `1 -> 13` |
| **PH7-D04** | **P0** | `JSLexer.Tokenize` lacked JS RegExp literal scanning (`/pattern/flags`), aborting Juice Shop `main.js` | `pkg/crawler/js_parser.go` | **FIXED** | `TestPhase7_JSLexerRegexLiteralAndAngularRestExtraction`; Juice Shop `cand 6 -> 48` |
| **PH7-D05** | **P0** | Bundle extractor omitted `/rest/*`, Angular `this.http.*`, Webpack scoped vars (`og=...`), object route maps (`sg={...}`), relative paths | `pkg/crawler/bundle_extractor.go`, `pkg/crawler/route_normalizer.go` | **FIXED** | `TestPhase7_WebpackIIFEAndRelativeObjectMapExtraction`; crAPI JS `cand 0 -> 31` |
| **PH7-D06** | **P0** | Naive `strings.TrimRight(base, "/") + path` broke non-root targets like `http://127.0.0.1:5000/ui/` | `cmd/felix/assess_authz.go`, `cmd/felix/assess_cmd.go`, `pkg/webvuln/engine.go`, `pkg/apisec/engine.go` | **FIXED** | `TestPhase7_ResolveTargetEndpointURL_NonRootAndRootPaths`, `TestPhase7_BuildEndpointURL_NonRootBasePath`; VAmPI `/ui/` `v6` `17` endpoints & authz verified |
| **PH7-D07** | **P0** | Status mapping drift (`CONFIRMED`/`POTENTIAL` -> `OBSERVED`/`NOT TESTED`), stale `summary.total_findings`, contradictory commercial zero-finding text | `pkg/report/normalize.go`, `pkg/report/summary.go`, `pkg/investigation/live_session.go`, `cmd/felix/assess_cmd.go` | **FIXED** | `TestPhase7_NormalizeVerificationStatusAndSummarySync`; 100% JSON/SARIF/Commercial/HTML parity across all 17 live scans |
| **PH7-D08** | **P0** | `extractHardeningDiscriminator` collapsed distinct headers (`HDR-CSP`, `HDR-NOSNIFF`) under generic category; property paths collided | `pkg/correlation/fingerprint.go`, `pkg/correlation/dedup.go` | **FIXED** | `TestPhase7_DistinctSecurityHeadersDoNotDeduplicate` |
| **PH7-D09** | **P0** | `FormatSafeCurl` passed `f.Target` instead of concrete `f.Endpoint` | `pkg/investigation/prover.go` | **FIXED** | `TestPhase7_SafeCurlResolvesSubpathTargetCleanly`; verified on VAmPI & crAPI outputs |
| **PH7-D10** | **P1** | SPA catch-all `200 text/html` FP on `/.env`; `SSTI`/`NoSQLi`/`Traversal` lacked baseline negative diff & static guards | `pkg/webvuln/engine.go` | **FIXED** | `TestPhase7_InfoDisclosure_SPACatchAllAndSSTI_BaselineDiff`; 0 SPA `.env` FPs on Juice Shop |
| **PH7-D11** | **P1** | Retest omitted safe live provers (`CMDI`, headers, XFO, info-disc, BOLA, BOPLA) and misreported untested checks or stale metadata | `pkg/investigation/prover.go`, `pkg/investigation/retest.go`, `pkg/investigation/remediation.go` | **FIXED** | `TestPhase7_RetestNeverClaimsFixOnUntestedOrPotential`, `TestPhase7_RetestLiveProvers_CMDI_Headers_Info_Authz` |
| **PH7-D12** | **P2** | Multi-identity `CrawlMultiIdentity` inflated `DiscoverySummary` counts (`2x`/`4x`) across identities | `pkg/crawler/recursive.go` | **FIXED** | `TestPhase7_MultiIdentitySummaryDeduplicatesAcrossIdentities` |
| **PH7-D13** | **P0** *(Added in Live Authz Audit)* | Authz discovery missed nested `/me` (`{"data":...}`) ownership unwrap, `"user"` owner key, `/_debug` BOLA collection binding, `/_debug` BFLA hint, DB-reset exclusions, and nested plaintext `password` BOPLA schemas | `cmd/felix/assess_authz.go`, `pkg/bola/discovery.go`, `pkg/bola/engine.go`, `pkg/bfla/discovery.go`, `pkg/bfla/engine.go`, `pkg/bopla/discovery.go` | **FIXED** | `TestPhase7_BOLA_NestedMeAnchor_UserOwnerField_AndDebugCollectionBinding`, `TestPhase7_BFLA_DebugUnderscorePathAndStateResetDestructive`, `TestPhase7_BOPLA_PlaintextPasswordAndNestedOpenAPISchema`; VAmPI `v4` verifies BOLA+BFLA+BOPLA live |

---

## 2. Modified & Added Source Files Inventory

*(Total tracked diff against `HEAD` `4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9`: 32 modified files, `2283` insertions, `586` deletions — excluding generated test evidence timestamps under `test/evidence/*` and `test/lab/lab_results.json` rewritten during `go test ./...`.)*

### 2.1 Core Implementation Edits
- `cmd/felix/assess_authz.go` (`+113/-...`): OpenAPI spec ingestion wiring, subpath URL resolution (`ResolveTargetEndpointURL`), `isSafeCandidateGETPath` DB-reset exclusions + `/me`/`/whoami`/`/_debug`/`/rest/`/`/identity/`/`/workshop/` hints.
- `cmd/felix/assess_cmd.go` (`+350` lines block): `--synthetic-fixture` gating separate from `--allow-loopback`, post-enrichment `DeduplicateFindings` / `Prioritize` / `Summarize` / `RecalculateReportRisk` / `BuildCommercialReport` synchronization.
- `pkg/webvuln/engine.go` (`+310` lines block): `buildEndpointURL` subpath safety, `.js`/static-asset guards, CMDI/SSTI/NoSQLi/Traversal baseline + negative control differentials, SPA soft-404 catch-all filtering, metadata `HEAD` vs fixture `.env` redaction.
- `pkg/crawler/js_parser.go`, `bundle_extractor.go`, `route_normalizer.go`, `recursive.go`: JS RegExp literal lexing, `/rest/*` & microservice prefix patterns, Angular/Axios/Fetch/XHR + scoped constants + Webpack object route maps, relative route normalization, deduplicated multi-identity `DiscoverySummary`.
- `pkg/apisec/engine.go`: Subpath-safe URL resolution and OpenAPI route support.
- `pkg/bola/discovery.go`, `pkg/bola/engine.go`: `"user"` / `"user_name"` / `"author_id"` / `"createdby"` owner keys, recursive envelope unwrapping (`buildIdentityAnchors`), `/_debug` / `/all` / `/list` / `/summary` collection-to-OpenAPI item binding.
- `pkg/bfla/discovery.go`, `pkg/bfla/engine.go`: `/_debug`, `/_admin`, `/_internal`, `/_metrics`, `/_config` hints; `/createdb`, `/initdb`, `/resetdb` destructive exclusion.
- `pkg/bopla/discovery.go`: Unmasked plaintext `password` / `secret` / `token` `CREDENTIALS` sensitivity rules; recursive `items`/`properties` OpenAPI schema property indexing.
- `pkg/auth/engine.go`, `pkg/auth/verifier.go`: Passive cookie / unconfirmed auth finding ceiling enforced at `SUSPECTED`.
- `pkg/correlation/fingerprint.go`, `pkg/correlation/dedup.go`: Security header title discrimination & `property_path` fingerprint discrimination.
- `pkg/report/normalize.go`, `pkg/report/summary.go`: Canonical verification status normalization & `RecalculateReportRisk` post-enrichment synchronization.
- `pkg/investigation/live_session.go`, `prover.go`, `retest.go`, `remediation.go`: `cleanup_status` preservation, concrete `FormatSafeCurl` endpoint URLs, live re-provers (`CMDI`, headers, XFO, info-disc, BOLA, BOPLA), fail-closed retest verdicts.
- Existing test alignment (`cmd/felix/exit_code_test.go`, `cmd/felix/report_apk_cmd_test.go`, `test/lab/lab_test.go`).

### 2.2 New Phase 7 Regression Test Suites (`10` Files, `19` Tests)
- `cmd/felix/assess_phase7_test.go` (3 tests)
- `pkg/auth/auth_phase7_test.go` (2 tests)
- `pkg/bfla/discovery_phase7_test.go` (1 test)
- `pkg/bola/discovery_phase7_test.go` (1 test)
- `pkg/bopla/discovery_phase7_test.go` (1 test)
- `pkg/correlation/fingerprint_phase7_test.go` (1 test)
- `pkg/crawler/bundle_phase7_test.go` (3 tests)
- `pkg/investigation/retest_phase7_test.go` (3 tests)
- `pkg/report/report_phase7_test.go` (1 test)
- `pkg/webvuln/webvuln_phase7_test.go` (3 tests)
