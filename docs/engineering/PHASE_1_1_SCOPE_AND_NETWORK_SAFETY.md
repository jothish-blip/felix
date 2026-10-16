# Engineering Report: Phase 1.1 — Authorized Target Scope and Network Safety

**Document ID:** FELIX-P1-001  
**Work Package:** Phase 1.1 — Authorized Target Scope and Network Safety  
**Phase:** Phase 1 — Assessment Safety and Common Data Model  
**Status:** COMPLETE — Awaiting Exit-Gate Approval  
**Date:** 2026-10-15  

---

## 1. Executive Summary

Phase 1.1 establishes that FELIX strictly and consistently enforces authorized target scope, input validation, redirect governance, and socket-level network safety across all assessment workflows.

Following the completion of Phase 0 and tasks `FELIX-P0-001` (SSRF and Redirect Safety), `FELIX-P0-002` (Unified Secret and Evidence Redaction), and `FELIX-P0-003` (Configuration Reliability and Fallbacks), Phase 1.1 resolves all remaining scope governance and network safety boundaries before initiating Phase 1.2 (Common Asset Model).

### Key Accomplishments in Phase 1.1:
1. **Target URL Validation & Normalization:** Implemented central, strict validation in `pkg/crawler/scope.go` (shared by `pkg/assessment` and `cmd/felix`). Targets with unsupported schemes (non-HTTP/HTTPS), malformed hosts, or embedded credentials (`user:pass@host`) are strictly rejected prior to any network request. Canonical normalization strips default ports and normalizes case and paths.
2. **Discovered Endpoint Network Safety:** Remedied unconstrained cloud service discovery in `pkg/cloud/detector.go` and candidate probing in `pkg/api/detector.go`. Third-party services discovered in client assets (S3 buckets, Firebase databases, Supabase instances) outside the authorized assessment scope are never probed across the network; they are recorded as informational findings (`SeverityInfo`, Category: `Discovered Cloud Service (Out of Scope)`).
3. **Exclusion Governance:** Enhanced `pkg/crawler/scope.go` and `pkg/crawler/crawler.go` to enforce exact host exclusions, wildcard host exclusions (`*.internal.domain.com`), and path prefix exclusions. Exclusions consistently override any broader scope rules across both standalone crawler and assessment pipelines.
4. **Socket-Level SSRF Safety Across All CLI Assessment Engines:** Integrated `crawler.NewSafeTransport` into all production assessment execution paths in `cmd/felix/assessment_cmd.go` (`authz`, `apisec`, `webvuln`, `sessionsec`, `businesslogic`, `cloudsec`). Every outbound request is pinned to resolved, verified IP addresses, preventing SSRF, DNS rebinding, and unauthorized connection to loopback, link-local, private RFC 1918, or cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`).
5. **Zero Regression Guarantee:** Preserved all prior work from `FELIX-P0-001`, `P0-002`, and `P0-003`. `benchmarks/results/latest.json` remains completely clean and untouched. All 21 packages across `./pkg/...` and `./cmd/...` pass `go test` and `go vet` cleanly.

---

## 2. Architecture and Security Flow

### Scope and Target Processing Pipeline

```
+---------------------------------------------------------------------------------+
|                                 Input Target URL                                |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       pkg/crawler.ValidateTargetURL()                           |
|  - Scheme must be http or https                                                 |
|  - Hostname must be non-empty and well-formed                                    |
|  - Embedded credentials (user:pass@host) STRICTLY PROHIBITED                    |
|  - Reject malformed or empty strings -> Exit Code 2                             |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       pkg/crawler.NormalizeTargetURL()                          |
|  - Canonical scheme and hostname to lowercase                                   |
|  - Strip default ports (:80 for http, :443 for https)                           |
|  - Normalize trailing slashes and preserve query parameters                     |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       pkg/crawler.Scope & Exclusions                            |
|  - Mode: same-origin | subdomains | explicit                                    |
|  - ExcludeHost (exact & wildcard *.domain)                                      |
|  - ExcludePathPrefix (/admin, /logout)                                          |
|  - Exclusions ALWAYS override broader scope (IsExcluded takes precedence)       |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       SafeTransport & Socket-Level Dialing                      |
|  - Pre-dial DNS resolution & validation against ProhibitedIPReason              |
|  - Direct IP connection pinning (immune to TOCTOU DNS rebinding)                |
|  - TLS SNI & Host preservation                                                  |
|  - Redirect loop & destination verification                                     |
|  - Absolute refusal: 127.0.0.0/8, 169.254.0.0/16, 169.254.169.254, fd00:ec2::254|
+---------------------------------------------------------------------------------+
```

---

## 3. Subsystem Audit and Gaps Remedied

### Subsystem 1: Target URL Validation & Normalization
- **Prior State:** `pkg/crawler/scope.go` accepted raw target URLs directly without schema or credential validation. A URL containing embedded credentials (e.g., `http://admin:pass@target.com`) was parsed without error, creating risk of credential stuffing, credential leakage in logs, and unexpected authorization headers.
- **Remediation:**
  - Implemented `ValidateTargetURL(raw string) (*url.URL, error)` in `pkg/crawler/scope.go`.
  - Implemented `NormalizeTargetURL(raw string) (string, error)` in `pkg/crawler/scope.go`.
  - Refactored `pkg/assessment/scope.go` to delegate to `crawler.ValidateTargetURL` and `crawler.NormalizeTargetURL`, ensuring a single source of truth across both standalone scan and multi-target assessment modes.
  - Updated `cmd/felix/scan_cmd.go` to validate and normalize all CLI targets before crawler or detector instantiation. Any validation failure exits immediately with exit code 2.

### Subsystem 2: Discovered Endpoint Scope Governance
- **Prior State:** `pkg/cloud/detector.go` parsed client JavaScript assets for cloud infrastructure references (Amazon S3 buckets, Firebase real-time databases, Google Cloud Storage buckets, Supabase endpoints). It immediately executed active HTTP requests against all discovered endpoints, even when those endpoints belonged to third parties and were outside the authorized assessment scope.
- **Remediation:**
  - Added scope awareness to `pkg/cloud/detector.go`: `NewDetector(client *Client, isAllowed func(string) bool)`.
  - Prior to active probing in `Audit()`, the detector evaluates `d.isAllowed(svc.URL)`.
  - If the endpoint is outside the authorized target scope, active network requests are skipped entirely. An informational finding is emitted:
    - **Category:** `Discovered Cloud Service (Out of Scope)`
    - **Severity:** `SeverityInfo`
    - **Description:** `Discovered <Provider> service reference in client assets; active probing skipped (outside authorized assessment scope)`
  - Added scope filtering in `pkg/api/detector.go` to ensure candidate paths and CORS targets are filtered against `isAllowed` and `isExcluded` prior to active probing.

### Subsystem 3: Exclusions and Scope Precedence
- **Prior State:** `pkg/crawler/scope.go` only evaluated whether an asset was allowed under the broad mode (`ScopeSameOrigin`, `ScopeSubdomains`, `ScopeExplicit`). It lacked support for explicit target exclusions.
- **Remediation:**
  - Added exclusion tracking to `pkg/crawler.Scope`:
    - `ExcludeHost(host string)`: Supports exact hostnames and wildcard domain patterns (e.g. `*.internal.target.com`).
    - `ExcludePathPrefix(prefix string)`: Supports exclusion of sensitive paths (e.g. `/admin`, `/logout`, `/billing`).
    - `IsExcluded(rawURL string) (bool, string)`: Evaluates candidate URLs against registered exclusions and returns descriptive reasons.
  - Enforced that `IsExcluded` takes strict precedence: in `Scope.IsAllowed`, if `IsExcluded` returns true, `IsAllowed` immediately returns false regardless of whether the domain matches the broad scope mode.
  - Enforced `isExcluded` in `pkg/crawler/crawler.go` during asset downloads and source map processing.

### Subsystem 4: Engine Transports & SSRF Protection
- **Prior State:** While `FELIX-P0-001` introduced `crawler.NewSafeTransport`, only the core crawler used it by default. The standalone CLI assessment commands in `cmd/felix/assessment_cmd.go` (`authz`, `apisec`, `webvuln`, `sessionsec`, `businesslogic`, `cloudsec`) created default HTTP clients without `SafeTransport`.
- **Remediation:**
  - Updated `cmd/felix/assessment_cmd.go` so that all assessment execution commands equip their engine HTTP clients with `crawler.NewSafeTransport`:
    - `authzHTTPClient` (line 1982)
    - `apisecHTTPClient` (line 2380)
    - `webvulnHTTPClient` (line 2826)
    - `sessionHTTPClient` (line 3352)
    - `blogicHTTPClient` (line 4385)
    - `cloudsec` engine configuration (line 3886)
  - Engine internal methods (`scopedClient`) maintain clean fallbacks to `http.DefaultTransport` when unconfigured so mock and hermetic unit tests with `httptest.Server` (127.0.0.1) execute properly without tripping production SSRF filters.

---

## 4. Test Suite and Evidence

### 1. `pkg/crawler/scope_test.go` (New)
Table-driven unit tests verifying:
- **`TestValidateTargetURL`**: Valid HTTP and HTTPS URLs pass; empty/whitespace URLs, unsupported schemes (`file://`, `ftp://`, `javascript:`), embedded credentials (`user:pass@host`), and missing hostnames are rejected.
- **`TestNormalizeTargetURL`**: Default ports (80/443) stripped; non-default ports retained; scheme and hostname lowercased; trailing slashes normalized; queries retained.
- **`TestNewScope`**: Validation failures fail closed; empty mode defaults to `ScopeSameOrigin`; allowed hosts populated and case-normalized.
- **`TestScope_IsAllowed_Modes`**: Verifies `ScopeSameOrigin`, `ScopeSubdomains`, and `ScopeExplicit`, plus explicit rejection of non-HTTP(S) schemes (`data:`, `file:`, `javascript:`, `mailto:`).
- **`TestScope_Exclusions`**: Verifies exact host exclusions, wildcard domain exclusions, and path prefix exclusions override broader scope allowances.

### 2. `pkg/cloud/cloud_test.go`
- **`TestDetector_ScopeExclusion`**: Verifies that discovered external S3 and Firebase references in client assets are not actively probed over the network when outside authorized scope, and produce `SeverityInfo` findings.

### 3. `cmd/felix/scan_cmd_test.go`
- Added tests to `TestRunScan_CLIPrecedenceAndValidation`:
  - `embedded_credentials_in_target_URL`: `http://user:secret@target.local` -> Exit Code 2
  - `unsupported_target_scheme`: `file:///etc/passwd` -> Exit Code 2
  - `malformed_target_URL`: `http://` -> Exit Code 2

### 4. Full Repository Test Results
```text
ok      felix/pkg/api           5.462s
ok      felix/pkg/apisec        14.590s
ok      felix/pkg/assessment    12.658s
ok      felix/pkg/auth          2.882s
ok      felix/pkg/authz         1.841s
ok      felix/pkg/businesslogic 13.160s
ok      felix/pkg/cloud         2.588s
ok      felix/pkg/cloudsec      1.977s
ok      felix/pkg/config        2.355s
ok      felix/pkg/correlation   2.304s
ok      felix/pkg/crawler       9.406s
ok      felix/pkg/discovery     3.006s
ok      felix/pkg/operator      4.693s
ok      felix/pkg/report        3.692s
ok      felix/pkg/secrets       3.751s
ok      felix/pkg/sessionsec    2.618s
ok      felix/pkg/ui            (cached)
ok      felix/pkg/update        (cached)
ok      felix/pkg/verification  2.443s
ok      felix/pkg/webvuln       4.549s
ok      felix/cmd/felix         4.250s
```
- **Total Packages:** 21
- **Status:** 100% Passed
- **`go vet` Status:** Clean (0 warnings)
- **`go build` Status:** Clean (0 errors)
- **`git diff --check`:** Clean (0 whitespace/formatting issues)
- **Benchmark Integrity:** `benchmarks/results/latest.json` untouched and unmodified.

---

## 5. Exit-Gate Sign-Off

Phase 1.1 — Authorized Target Scope and Network Safety is fully implemented, verified, and documented.

All safety constraints were maintained throughout execution:
- Phase 1.2 (Common Asset Model) has NOT been started.
- Zero destructive git commands were executed.
- All baseline reports and previous task changes were preserved.

**Phase 1.1 is ready for formal review and acceptance.**
