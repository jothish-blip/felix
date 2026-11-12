# FELIX PHASE 7 — REGRESSION TEST & BUILD VERIFICATION REPORT

**Repository:** `C:\Jothish\felix`  
**Go Toolchain:** `go1.27.0 windows/amd64`  
**Verification Date:** 2026-11-12  

---

## 1. Full Repository Build, Vet & Test Suite Verification (`task-46085`)

Executed in `C:\Jothish\felix` after all Phase 7 source code edits and binary builds (`felix.exe` and `bin\felix.exe`):
- **`go build ./...`**: exit `0`
- **`go vet ./...`**: exit `0`
- **`go test -p 1 -count=1 ./...`**: exit `0` — **`48` tested packages passed (`ok`), `2` `[no test files]` (`felix/scratch`, `felix/test/lab/cmd/multiclass`), `0` failures**

*(Note: `go test -race ./...` is unsupported on this host without CGO enabled, as documented in the baseline audit: `go: -race requires cgo`.)*

---

## 2. Per-Package `go test -p 1 -count=1 ./...` Results

| Package | Status | Duration | Package | Status | Duration |
| :--- | :---: | :---: | :--- | :---: | :---: |
| `felix/benchmarks` | `ok` | `2.375s` | `felix/pkg/fuzzer` | `ok` | `50.386s` |
| `felix/cmd/felix` | `ok` | `72.405s` | `felix/pkg/intelligence` | `ok` | `1.341s` |
| `felix/pkg/api` | `ok` | `7.022s` | `felix/pkg/investigation` | `ok` | `2.549s` |
| `felix/pkg/apisec` | `ok` | `4.001s` | `felix/pkg/mobile` | `ok` | `23.662s` |
| `felix/pkg/apk` | `ok` | `5.337s` | `felix/pkg/monitor` | `ok` | `4.156s` |
| `felix/pkg/assessment` | `ok` | `45.465s` | `felix/pkg/notify` | `ok` | `5.155s` |
| `felix/pkg/auth` | `ok` | `7.672s` | `felix/pkg/oast` | `ok` | `2.440s` |
| `felix/pkg/authz` | `ok` | `2.701s` | `felix/pkg/operator` | `ok` | `4.832s` |
| `felix/pkg/bfla` | `ok` | `2.615s` | `felix/pkg/policy` | `ok` | `1.469s` |
| `felix/pkg/bola` | `ok` | `3.099s` | `felix/pkg/provenance` | `ok` | `1.801s` |
| `felix/pkg/bopla` | `ok` | `2.721s` | `felix/pkg/remediation` | `ok` | `2.185s` |
| `felix/pkg/businesslogic` | `ok` | `3.168s` | `felix/pkg/report` | `ok` | `11.997s` |
| `felix/pkg/ci` | `ok` | `11.139s` | `felix/pkg/secrets` | `ok` | `1.546s` |
| `felix/pkg/clierror` | `ok` | `0.982s` | `felix/pkg/sessionsec` | `ok` | `2.607s` |
| `felix/pkg/cloud` | `ok` | `3.211s` | `felix/pkg/swarm` | `ok` | `8.256s` |
| `felix/pkg/cloudsec` | `ok` | `2.927s` | `felix/pkg/ui` | `ok` | `0.872s` |
| `felix/pkg/commercial` | `ok` | `2.457s` | `felix/pkg/update` | `ok` | `3.879s` |
| `felix/pkg/compliance` | `ok` | `7.514s` | `felix/pkg/verification` | `ok` | `1.405s` |
| `felix/pkg/config` | `ok` | `1.744s` | `felix/pkg/webvuln` | `ok` | `2.346s` |
| `felix/pkg/correlation` | `ok` | `0.526s` | `felix/pkg/workflow` | `ok` | `2.588s` |
| `felix/pkg/crawler` | `ok` | `8.192s` | `felix/scratch` | `[no test files]` | — |
| `felix/pkg/crawler/browser` | `ok` | `113.490s` | `felix/scripts/packaging` | `ok` | `63.378s` |
| `felix/pkg/cve` | `ok` | `69.881s` | `felix/test` | `ok` | `132.596s` |
| `felix/pkg/discovery` | `ok` | `2.248s` | `felix/test/lab` | `ok` | `20.180s` |
| `felix/pkg/exploit` | `ok` | `2.694s` | `felix/test/lab/cmd/multiclass` | `[no test files]` | — |

---

## 3. Phase 7 Regression Tests Added (`10` Files, `19` Tests)

| Test File | Test Function(s) | Coverage Verified |
| :--- | :--- | :--- |
| `cmd/felix/assess_phase7_test.go` | `TestPhase7_ResolveTargetEndpointURL_NonRootAndRootPaths`, `TestPhase7_OpenAPIIngestionFromNonRootUI`, `TestPhase7_OpenAPIIgnoresSPAFallbackAndMalformedSpecSafely` | Non-root subpath target resolution, OpenAPI ingestion from `/ui/`, HTML SPA fallback & malformed spec safety |
| `pkg/webvuln/webvuln_phase7_test.go` | `TestPhase7_CmdiFalsePositiveElimination_And_TruePositiveDifferential`, `TestPhase7_InfoDisclosure_SPACatchAllAndSSTI_BaselineDiff`, `TestPhase7_BuildEndpointURL_NonRootBasePath` | CMDI FP elimination on HTML/JS/JSON, real CMDI differential TP, SPA `/.env` fallback filtering, SSTI baseline diff, URL resolution |
| `pkg/crawler/bundle_phase7_test.go` | `TestPhase7_JSLexerRegexLiteralAndAngularRestExtraction`, `TestPhase7_WebpackIIFEAndRelativeObjectMapExtraction`, `TestPhase7_MultiIdentitySummaryDeduplicatesAcrossIdentities` | JS RegExp literal lexing, `/rest/*` & Angular extraction, Webpack constants/object map concat, multi-role `DiscoverySummary` dedup |
| `pkg/auth/auth_phase7_test.go` | `TestPhase7_CookieObservationsAreNotPromotedToConfirmed`, `TestPhase7_BuildMissingAuthFindingUnconfirmedStaysSuspected` | Cookie & missing-auth observations capped at `SUSPECTED` without false confirmation |
| `pkg/bola/discovery_phase7_test.go` | `TestPhase7_BOLA_NestedMeAnchor_UserOwnerField_AndDebugCollectionBinding` | Nested `/me` envelope unwrapping, `"user"` owner field, `/_debug` collection binding to OpenAPI item template |
| `pkg/bfla/discovery_phase7_test.go` | `TestPhase7_BFLA_DebugUnderscorePathAndStateResetDestructive` | `/_debug` privileged hint recognition and `/createdb`/`/initdb`/`/resetdb` destructive guard |
| `pkg/bopla/discovery_phase7_test.go` | `TestPhase7_BOPLA_PlaintextPasswordAndNestedOpenAPISchema` | Plaintext password sensitivity detection & recursive `items`/`properties` OpenAPI schema walk |
| `pkg/correlation/fingerprint_phase7_test.go` | `TestPhase7_DistinctSecurityHeadersDoNotDeduplicate` | Distinct header findings (`HDR-CSP`, `HDR-NOSNIFF`, `HDR-XFO`) preserved without deduplication collision |
| `pkg/report/report_phase7_test.go` | `TestPhase7_NormalizeVerificationStatusAndSummarySync` | `CONFIRMED -> VERIFIED` / `POTENTIAL -> DETECTED` normalization, post-enrichment `summary` & `commercial_report` sync |
| `pkg/investigation/retest_phase7_test.go` | `TestPhase7_RetestNeverClaimsFixOnUntestedOrPotential`, `TestPhase7_SafeCurlResolvesSubpathTargetCleanly`, `TestPhase7_RetestLiveProvers_CMDI_Headers_Info_Authz` | Fail-closed `--retest`, concrete subpath `safe_curl_command`, live provers across CMDI, headers, info-disc, authz |
