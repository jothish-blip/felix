# FELIX PHASE 7 — API DISCOVERY REPORT

**Repository:** `C:\Jothish\felix`  
**Targets Validated:** OWASP VAmPI (`127.0.0.1:5000`, OpenAPI 3.0), OWASP Juice Shop `v20.2.0` (`127.0.0.1:3000`, Angular SPA), OWASP crAPI `v1.1.5` (`127.0.0.1:8888`, React SPA)  
**Completion Date:** 2026-11-12  

---

## 1. Executive Summary

Phase 6 revealed severe discovery blindness across both OpenAPI-documented APIs and JavaScript single-page applications (SPAs):
- VAmPI served `/openapi.json` (`200 OK`), yet FELIX discovered only **1 endpoint** (`res=1` / `"Discovered 1 attack surface endpoints"`) because OpenAPI parsing was never wired into `assess`.
- crAPI served Webpack/React bundles, yet FELIX extracted **`0` candidate endpoints (`cand=0`)**, reporting only `2` attack surface endpoints.
- Juice Shop's Angular `main.js` aborted AST scanning on a regex literal (`Line 6552:6405: Unterminated string literal`) and missed `/rest/*` routes, leaving discovery at **`cand=6`**, `res=11`.
- Multi-identity crawls multiplied identical endpoints linearly (`cand=6 -> 12 -> 24`, `js=3 -> 6 -> 12`) in `DiscoverySummary`.

Phase 7 repaired all four architectural bottlenecks:
- VAmPI attack surface grew from **1 -> 13 endpoints** (and **1 -> 17** from `/ui/` non-root target).
- Juice Shop discovery grew from **`cand=6` -> `cand=48`** (**`24 -> 66` total discovered attack surface endpoints**).
- crAPI JS extraction grew from **`cand=0` -> `cand=31`** (**`2 -> 33` total discovered attack surface endpoints**).

---

## 2. Root Causes & Architectural Remediations

### 2.1 OpenAPI Specification Ingestion (`PH7-D03`)
- **Defect:** `cmd/felix/assess_authz.go` fetched `/openapi.json`, emitted one `OPENAPI_SPEC` observation, and dropped the spec body without calling `pkg/api.NewSpecParser()`.
- **Fix:**
  - Wired `api.NewSpecParser().ParseSpecificationData(...)` into `cmd/felix/assess_authz.go`, seeding parsed operations, HTTP methods, path templates, query/path parameters, and schema properties into discovery, `bola`, `bfla`, `bopla`, `apisec`, and `webvuln`.
  - Added strict validation rejecting HTML SPA catch-all fallbacks (`text/html`) and malformed YAML/JSON specs instead of crashing or polluting candidates (`TestPhase7_OpenAPIIgnoresSPAFallbackAndMalformedSpecSafely`).
  - Handled non-root `--target` paths (e.g., `http://127.0.0.1:5000/ui/`) by resolving well-known spec URLs against both base path and origin root (`TestPhase7_OpenAPIIngestionFromNonRootUI`).

### 2.2 JS Lexer & SPA Route Extraction (`PH7-D04`, `PH7-D05`)
- **JS RegExp Literal Lexing (`pkg/crawler/js_parser.go`):** Added context-sensitive JavaScript RegExp literal scanning (`/pattern/flags`) to `JSLexer.Tokenize` plus bounded recovery on malformed tokens so Angular `main.js` (`v20.2.0`) lexes cleanly without aborting at line 6552 (`TestPhase7_JSLexerRegexLiteralAndAngularRestExtraction`).
- **Expanded API Route Patterns & HTTP Client AST Sinks (`pkg/crawler/bundle_extractor.go`):**
  - Expanded `rxDirectAPIPath` and template/AST filters to recognize `/rest/*`, `/identity/*`, `/workshop/*`, `/community/*`, `/chatbot/*`, `/users/*`, `/books/*`, `/_debug`, and standard API prefixes.
  - Added Angular `this.http.get/post/put/delete(...)`, Axios, `fetch(...)`, and XHR call extraction.
  - Added function-scoped variable & object-literal map extraction (e.g., `og = "identity/"`, `sg = { LOGIN: "api/auth/login" }`, concatenated `og + sg.LOGIN`) common in minified Webpack/CRA React bundles like crAPI (`TestPhase7_WebpackIIFEAndRelativeObjectMapExtraction`).
- **Relative Route Normalization (`pkg/crawler/route_normalizer.go`):** Updated `NormalizeRouteCandidate` to retain validated API-looking relative routes rather than dropping all paths without a leading `/`, while rejecting static asset noise.

### 2.3 Candidate Collection, Safety Filtering & Authz Endpoint Binding (`cmd/felix/assess_authz.go`, `pkg/bola/discovery.go`, `pkg/bfla/discovery.go`)
- Filtered DB-mutating setup routes (`/createdb`, `/initdb`, `/resetdb`, `/reset-db`) from read-only GET candidate prefetching (`isSafeCandidateGETPath`) and included self-identity/debug paths (`/me`, `/whoami`, `/rest/`, `/identity/`, `/workshop/`, `/community/`, `/_debug`).
- Added collection-to-item OpenAPI binding in `pkg/bola/discovery.go` so collection responses from `/_debug`, `/all`, `/list`, `/summary`, etc. map discovered identifiers back onto real OpenAPI item templates (e.g., `/users/v1/{username}`) instead of synthesizing bogus `/users/v1/_debug/{username}` 404 routes.

### 2.4 Non-Root Base Path Joining & Multi-Identity Summary Deduplication (`PH7-D06`, `PH7-D12`)
- Replaced naive `strings.TrimRight(base, "/") + path` string concatenation across `cmd/felix/assess_authz.go`, `pkg/webvuln/engine.go` (`buildEndpointURL`), and `pkg/apisec/engine.go` with origin-aware `url.URL` resolution (`TestPhase7_ResolveTargetEndpointURL_NonRootAndRootPaths`, `TestPhase7_BuildEndpointURL_NonRootBasePath`).
- Updated `CrawlMultiIdentity` in `pkg/crawler/recursive.go` so `DiscoverySummary` reports deduplicated unique counts across identities alongside per-identity visibility (`TestPhase7_MultiIdentitySummaryDeduplicatesAcrossIdentities`).

---

## 3. Before vs. After Discovery Metrics (Live Targets)

| Target | Metric | Phase 6 (`j4`/`v4`/`c4`/`v6`) | Phase 7 (`j4`/`v4`/`c4`/`v6`) | Delta |
| :--- | :--- | :---: | :---: | :--- |
| **VAmPI** (`v4_multirole_mut`) | Total discovered attack surface endpoints | 1 | **13** | **+1,200%** (OpenAPI 3.0 parsed) |
| **VAmPI** (`v3_multirole_ro`) | Total discovered endpoints across roles | 1 (`conf=4` dup) | **13** (`conf=1` dedup) | Deduplicated |
| **VAmPI** (`v6_ui_multirole_mut`, `/ui/`) | Attack surface from non-root target | 4 | **17** | **+325%** (`conf=1, cand=1, js=2`) |
| **Juice Shop** (`j4_multirole_mut`) | Unique candidate endpoints (`cand`) | 6 (inflated to 24 across 4 contexts) | **48** (unique across contexts) | **+700% unique** |
| **Juice Shop** (`j4_multirole_mut`) | Reported attack surface endpoints | 24 | **66** | **+175%** |
| **crAPI** (`c4_multirole_mut`) | Unique JS bundle candidate endpoints (`cand`) | 0 | **31** | **0 -> 31** |
| **crAPI** (`c4_multirole_mut`) | Reported attack surface endpoints | 2 | **33** | **+1,550%** |

---

## 4. Residual Discovery Gaps (Observed on crAPI)

Honest live testing on OWASP crAPI `v1.1.5` exposed two remaining limitations:
1. **Unprefixed Relative Service Paths in Bundled React Services:** Some minified CRA modules define microservice path constants separated across nested helper functions or Redux action creators (e.g., `/api/mechanic/...` without the nginx gateway `/workshop` prefix or vice versa), limiting runtime match rates on unhinted sub-APIs (`cand=31` discovered, `ver=0` authenticated BOLA proofs).
2. **Dynamic Authenticated MailHog / Token-Chained Entities:** Endpoints requiring multi-step email verification (such as MailHog PIN/VIN activation for `/identity/api/v2/vehicle/{vehicleId}/location`) are seeded by test harnesses rather than auto-provisioned by FELIX's unauthenticated/single-token crawler unless seed objects already exist in the user's account.
