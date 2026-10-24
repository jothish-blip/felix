# Felix Source-Grounded Capability & Validation Matrix

**Release Target:** FELIX v2.0.0<br>
**Repository:** `C:\Jothish\felix` (`jothish-blip/felix`)<br>
**Phase:** 12 — Packaging and Release<br>
**Work Package:** P12.9 — Supported Coverage<br>
**Status:** Authoritative Implementation-Backed Matrix

---

## 1. Executive Summary & Verification Methodology

This document establishes the authoritative, evidence-backed inventory of technologies, input formats, assessment capabilities, operating environments, integrations, and operational limitations supported by the **FELIX Security Assessment CLI**.

Every statement in this document reflects the **actual codebase and automated test evidence** present in the repository (`cmd/felix`, `pkg/`, `scripts/`, and `test/`). Capabilities are distinguished between live-target verified, mock/fixture validated, cross-compiled, and explicitly unsupported non-goals.

### Standardized Support Levels

To prevent overstatement of capabilities, Felix classifies all features across six standardized support levels:

1. **Implemented and tested:** The capability is implemented in production code (`pkg/`, `cmd/felix`) and exercised by automated end-to-end or integration tests.
2. **Fixture/mock validated:** The capability is implemented and thoroughly tested using controlled local fixtures (`httptest.Server`, synthetic mock TCP sockets, or local archives); live third-party cloud/provider behavior remains unverified against public production endpoints in CI.
3. **Implemented, validation incomplete:** Code exists, but current automated test suites only exercise partial execution paths or edge cases.
4. **Partially supported:** Only specified sub-protocols, formats, HTTP methods, or restricted workflows are implemented; broader variations are not supported.
5. **Not supported:** The capability is absent or explicitly outside product design boundaries.
6. **Not verified:** Insufficient evidence exists in the repository to establish runtime support.

---

## 2. Comprehensive Capability Matrix by Assessment Domain

### A. Web Application Assessment & Discovery

| Subsystem / Capability | Support Level | Implementation Package | Primary CLI Entrypoint | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP/HTTPS Ingestion** | Implemented and tested | `pkg/crawler` | `felix scan <url>` | `pkg/crawler/crawler_test.go`: `TestCrawlConcurrently` | Local `httptest.Server` (HTTP/1.1 and TLS) | Supports HTTP/1.1 and HTTP/2 over TLS. Non-HTTP protocols (FTP, SSH) rejected immediately. |
| **Scope Enforcement** | Implemented and tested | `pkg/crawler` | `felix scan --scope same-origin\|subdomains\|explicit` | `pkg/crawler/crawler_test.go`: `TestCrossOriginScopeEnforcement`, `TestCrawler_ScopedRedirectEnforcement` | Redirect loops, cross-domain links, subdomain fixtures | Enforces strict host boundaries. Cross-domain redirects are blocked and recorded as negative evidence. |
| **SSRF & Private IP Protection** | Implemented and tested | `pkg/crawler` | `felix scan` (Active by default; `--allow-private` or `--allow-loopback` to disable) | `pkg/crawler/ssrf_test.go`: `TestSSRF_1_LoopbackIPv4Blocked`, `TestSSRF_6_CloudMetadataBlocked`, `TestSSRF_10_OutOfScopeRedirectRejected` | Synthetic socket dialer intercepting loopback, RFC 1918, link-local, and AWS metadata IP (`169.254.169.254`) | Prevents DNS rebinding and loopback probing unless explicitly overridden by authorized operators. |
| **JavaScript Bundle Deobfuscation & Route Extraction** | Implemented and tested | `pkg/crawler` | `felix scan <url>` | `pkg/crawler/bundle_test.go`: `TestP14_1_MinifiedJSLiteralPaths`, `TestP14_1_WebpackChunksAndAsyncTraversal`, `TestP14_1_FalsePositiveFiltration` | Webpack, Vite, and Next.js client bundle fixtures | Lexical static parsing only; extracts API routes, string literals, and endpoints without JavaScript runtime execution. |
| **Headless Browser Driver (Optional Library Feature)** | Partially supported (Fixture/mock validated) | `pkg/crawler` | Internal `BrowserDiscoveryOptions` (**No CLI flag**) | `pkg/crawler/browser_test.go`: `TestBrowserDiscovery_BrowserUnavailableFallback`, `TestBrowserDiscovery_JSRenderedRoute`, `TestBrowserDiscovery_OutOfScopeBlocked` | Synthetic Chromium mock CLI invocation, mock DOM dumps | **Library-level option only; no CLI flag exists on `felix scan`.** Felix embeds **no browser runtime or Chromium engine**. Requires external system-installed Chromium. Disabled by default (`opts.Enabled = false`). |
| **Passive Security Headers** | Implemented and tested | `pkg/api` | `felix scan <url>` | `pkg/api/api_test.go`: `TestSecurityHeaderDetection`, `TestHTTPSHSTSHandling` | HTTP mock responses with missing or malformed CSP, HSTS, XFO, XXP | Evaluates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. |
| **CORS Misconfiguration** | Implemented and tested | `pkg/api` | `felix scan <url>` | `pkg/api/api_test.go`: `TestCORSArbitraryOriginReflection`, `TestCORSWildcard`, `TestCORSCredentialBehavior` | Local HTTP mock echoing dynamic `Origin` and `Access-Control-Allow-Credentials` | Validates arbitrary origin reflection and credentialed wildcard combinations. Clamped to safe read-only preflight OPTIONS and GET checks. |
| **Resource & Concurrency Limits** | Implemented and tested | `pkg/crawler` | `felix scan --concurrency <n> --timeout <d>` | `pkg/crawler/rate_limiter_test.go`, `pkg/crawler/crawler_test.go`: `TestResponseSizeLimit` | Fast and slow mock servers, oversized streams | Default concurrency 10 workers; max response body clamped to 10MB; max crawl depth bounded. |

---

### B. Modern API Assessment & Reconciliation

| Subsystem / Capability | Support Level | Implementation Package | Primary CLI Entrypoint | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenAPI / Swagger Parsing** | Implemented and tested | `pkg/api` | `felix scan --spec <path/url>` | `pkg/api/reconciliation_test.go`: `TestP14_2_YAMLSpecificationParsing`, `TestP14_2_ExactDocumentedMatch` | OpenAPI 3.0.x (JSON/YAML) and Swagger 2.0 specs with circular refs | Parses declared paths, methods, parameters, and tags. Rejects malicious external `$ref` pointers. |
| **Topology Reconciliation** | Implemented and tested | `pkg/api` | `felix scan --spec <file>` | `pkg/api/reconciliation_test.go`: `TestP14_2_ParameterEquivalence`, `TestP14_2_SensitiveUserIDDetection` | Cross-referenced client bundle extracts and OpenAPI specs | Categorizes endpoints into Documented, Shadow, Sensitive Shadow, and Orphan/Missing routes. |
| **Live Shadow API Exploitability Prober** | Implemented and tested | `pkg/api` | `felix scan --probe` (alias `--probe-live`) | `pkg/api/prober_test.go`: `TestP14_3_HEADReturning200`, `TestP14_3_HTTP401AuthenticationRequired`, `TestP14_3_ZeroMutatingMethodsSent` | Mock endpoints simulating 200, 401, 403, 404, 429, 500 responses | **Read-oriented methods (`HEAD`, `OPTIONS`, `GET`).** Mutating HTTP verbs (`POST`, `PUT`, `DELETE`) are strictly blocked. Filters generic HTML fallback shells and custom 404s in fixtures, but cannot mathematically guarantee zero false positives against bespoke server behaviors. |
| **Declarative Multi-Tenant Profiles** | Implemented and tested | `pkg/api` | `felix target validate <file>`, `felix scan --profile <file>` | `pkg/api/target_test.go`: `TestTargetProfile_ValidYAML`, `TestTargetProfile_ProhibitedMutatingMethodInAllowedMethods` | Multi-tenant YAML profile fixtures (`felix.target.yml`) | Validates tenant schemas, identity headers, and resource ownership mappings. Rejects profiles containing mutating methods in probe rules. |
| **BOLA / Cross-Tenant Testing** | Implemented and tested | `pkg/api`, `pkg/authz` | `felix scan --profile <file> --cross-tenant` | `pkg/api/target_test.go`: `TestMultiTenantEngine_DualOptIn_Enforcement`, `TestMultiTenantEngine_CredentialIsolationAndMissingEnv` | Dual-tenant HTTP mock servers (`user_a` vs `user_b` resource access) | Requires dual opt-in (`--profile` and `--cross-tenant`). Injects credentials strictly via environment variables (`FELIX_AUTH_*`). Read-only verification. |
| **GraphQL Introspection Check** | Implemented and tested | `pkg/api` | `felix scan <url>` | `pkg/api/api_test.go`: `TestGraphQLIntrospectionEnabled`, `TestGraphQLProtectedEndpoint` | Mock GraphQL servers responding to `__schema` queries | Confirms whether schema introspection is publicly queryable. Does not fuzz complex mutations or subscriptions. |

---

### C. Cloud Security & BaaS Infrastructure

| Cloud Service / Resource | Support Level | Implementation Package | Detection Mechanism | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Supabase (REST & GraphQL)** | Fixture/mock validated | `pkg/cloud` | Passive bundle URL regex (`<project>.supabase.co`) $\to$ anonymous probe | `pkg/cloud/discovery_test.go`: `TestProbeSupabase`; `pkg/cloud/cloud_test.go`: `TestSupabaseDiscovery`, `TestSupabaseExposedResource` | Local `httptest.Server` returning mock PostgreSQL/PostgREST JSON and 401/403/200 codes | Detects exposed tables with Row Level Security (RLS) disabled. HTTP 401/403 classified as `NOT_EXPOSED`. Tested only via local mocks in CI. |
| **Firebase Realtime Database** | Fixture/mock validated | `pkg/cloud` | Passive regex (`<project>.firebaseio.com`) $\to$ anonymous `/.json?shallow=true` probe | `pkg/cloud/discovery_test.go`: `TestProbeFirebaseRTDB`; `pkg/cloud/cloud_test.go`: `TestFirebaseDiscovery`, `TestFirebaseOpenDatabase` | Local `httptest.Server` simulating Firebase REST responses (null, data, permission denied) | Distinguishes public read exposure from enforced Firebase security rules (`Permission denied`). Tested only via local mocks in CI. |
| **Google Cloud Firestore** | Fixture/mock validated | `pkg/cloud` | Passive project ID extraction $\to$ REST API probe | `pkg/cloud/discovery_test.go`: `TestProbeFirestore` | Mock Google APIs endpoint simulating document collections and 403 Forbidden | Verifies unauthenticated collection listing. Does not attempt write/delete mutations. Tested only via local mocks in CI. |
| **Amazon Web Services (AWS S3)** | Fixture/mock validated | `pkg/cloud`, `pkg/cloudsec` | Passive bucket regex (`s3.amazonaws.com/<bucket>` or `<bucket>.s3.amazonaws.com`) $\to$ `HEAD`/`GET` probe | `pkg/cloud/discovery_test.go`: `TestProbeAWSS3`; `pkg/cloudsec/cloudsec_test.go`: `TestCloudSec_External_S3` | Mock S3 XML endpoints returning `ListBucketResult` or `AccessDenied` | Identifies public anonymous bucket listing. Rejects write probes. Tested only via local mocks in CI. |
| **Google Cloud Storage (GCS)** | Fixture/mock validated | `pkg/cloud`, `pkg/cloudsec` | Passive bucket regex (`storage.googleapis.com/<bucket>`) $\to$ `GET` probe | `pkg/cloud/discovery_test.go`: `TestProbeGCS`; `pkg/cloudsec/cloudsec_test.go`: `TestCloudSec_External_GCPStorage` | Mock GCS XML/JSON endpoints returning bucket objects or 403 | Detects public bucket read permissions. Tested only via local mocks in CI. |
| **Azure Blob Storage** | Fixture/mock validated | `pkg/cloud`, `pkg/cloudsec` | Passive URL regex (`<account>.blob.core.windows.net/<container>`) $\to$ REST probe | `pkg/cloud/discovery_test.go`: `TestProbeAzureBlob`; `pkg/cloudsec/cloudsec_test.go`: `TestCloudSec_External_AzureBlob` | Mock Azure Blob endpoints returning `EnumerationResults` or 403 | Detects public container enumeration. Tested only via local mocks in CI. |
| **MinIO Storage** | Fixture/mock validated | `pkg/cloud` | S3-compatible endpoint matching | `pkg/cloud/discovery_test.go`: `TestProbeMinIO` | Local mock S3/MinIO XML responses | Operates through standard S3 API signatures. Tested only via local mocks in CI. |

---

### D. Database & Management Surfaces

| Engine / Service | Support Level | Implementation Package | Protocol & Inspection Method | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Elasticsearch** | Fixture/mock validated | `pkg/cloud` | HTTP REST API (port 9200): `GET /`, `GET /_cluster/health`, `GET /_cat/indices` | `pkg/cloud/discovery_test.go`: `TestProbeElasticsearch`; `pkg/cloud/access_test.go`: `TestVerifyElasticsearchAccess` | Local `httptest.Server` simulating Elasticsearch cluster metadata and 401 challenges | Evaluates unauthenticated cluster metadata read. Distinguishes service reachability, auth challenges, and data access. |
| **MongoDB** | Fixture/mock validated | `pkg/cloud` | Direct TCP wire protocol (port 27017): OP_QUERY `isMaster` handshake | `pkg/cloud/discovery_test.go`: `TestProbeMongoDB`; `pkg/cloud/access_test.go`: `TestVerifyMongoDBAccess` | Synthetic TCP mock server responding with BSON handshake and auth errors | Handshake verifies protocol reachability; collection read requires explicit bounded resource config. No credential cracking or data dumping. |
| **Redis** | Fixture/mock validated | `pkg/cloud` | Direct TCP wire protocol (port 6379): `PING\r\n` and bounded `GET <key>` | `pkg/cloud/discovery_test.go`: `TestProbeRedis`; `pkg/cloud/access_test.go`: `TestVerifyRedisAccess` | Synthetic TCP mock server responding with `+PONG` or `-NOAUTH` | Evaluates whether Redis requires authentication (`-NOAUTH`). Does not issue destructive commands (`FLUSHALL`, `CONFIG`). |
| **PostgreSQL** | Fixture/mock validated | `pkg/cloud` | Direct TCP wire protocol (port 5432): StartupMessage and SSLRequest negotiation | `pkg/cloud/discovery_test.go`: `TestProbePostgreSQL`; `pkg/cloud/access_test.go`: `TestVerifyPostgreSQLAccess` | Synthetic TCP mock server returning SSL and Authentication negotiation bytes | Confirms database service identification and authentication challenges. Does not execute SQL injection or table dumps. |
| **MySQL** | Fixture/mock validated | `pkg/cloud` | Direct TCP wire protocol (port 3306): Initial Handshake Packet parsing | `pkg/cloud/discovery_test.go`: `TestProbeMySQL`; `pkg/cloud/access_test.go`: `TestVerifyMySQLAccess` | Synthetic TCP mock server returning MySQL protocol handshake packets | Extracts MySQL server version and authentication challenge. Does not attempt brute-force authentication. |
| **PostgREST** | Fixture/mock validated | `pkg/cloud` | HTTP REST API: Regex matching error signatures (`PGRST\d{3}`) and schema introspection | `pkg/cloud/discovery_test.go`: `TestProbePostgREST` | Local mock HTTP server returning PostgREST JSON responses | Identifies exposed PostgREST database APIs. Does not modify database state. |
| **Hasura GraphQL** | Fixture/mock validated | `pkg/cloud` | HTTP GraphQL API: Error signature matching (`"code":"validation-failed"`) | `pkg/cloud/discovery_test.go`: `TestProbeHasura` | Local mock HTTP server returning Hasura GraphQL errors | Identifies exposed Hasura instances and public schema endpoints. |
| **Mongo Express** | Fixture/mock validated | `pkg/cloud` | HTTP Management Portal (port 8081): Title and UI header detection | `pkg/cloud/discovery_test.go`: `TestProbeMongoExpress` | Local mock HTTP server serving Mongo Express HTML portal | Detects unauthenticated administrative web interfaces vs basic auth challenges. |

---

### E. Android APK Analysis

| Analysis Capability | Support Level | Implementation Package | Primary CLI Entrypoint | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Archive Intake & Validation** | Implemented and tested | `pkg/apk` | `felix apk <app.apk>`, `felix scan <app.apk>` | `pkg/apk/intake_test.go`: `TestIntake_MinimalStructurallyValidAPK`, `TestIntake_CompressionRatioZipBomb` | Valid APKs, corrupted ZIPs, directory targets, zip bomb fixtures | Validates ZIP magic bytes (`PK\x03\x04`), enforces max compressed/uncompressed size limits, and defends against directory traversal. |
| **Binary AXML Manifest Decoding** | Implemented and tested | `pkg/apk` | `felix apk --analyze <app.apk>`, `felix scan <app.apk>` | `pkg/apk/manifest_test.go`: `TestManifest_ParseAXML_Valid`, `TestAPK_AXML_BoundsAndChunkValidation` | Binary AXML string pools, chunk boundaries, UTF-8/UTF-16 pools | Extracts package name, version codes, min/target SDK versions, and custom permissions from compiled `AndroidManifest.xml`. |
| **Exported Component Auditing** | Implemented and tested | `pkg/apk` | `felix apk --analyze <app.apk>` | `pkg/apk/manifest_test.go`: `TestAnalyze_ExportedComponents_AllFiveTypes`, `TestAnalyze_TargetSDK31_OmittedExported_WithIntentFilters` | Multi-component manifests with Activities, Services, Receivers, and Providers | Identifies exported components lacking permission barriers. Handles Android 12 (SDK 31) implicit exported default rules. |
| **Manifest Security Flags** | Implemented and tested | `pkg/apk` | `felix apk --analyze <app.apk>` | `pkg/apk/manifest_test.go`: `TestAnalyze_DebuggableExplicitTrue`, `TestAnalyze_BackupEnabled` | Synthetic manifests with debuggable, allowBackup, and network security configs | Detects `android:debuggable=true`, `android:allowBackup=true`, and cleartext HTTP network configurations. |
| **DEX Bytecode String Extraction** | Implemented and tested | `pkg/apk` | `felix apk --analyze <app.apk>` | `pkg/apk/artifact_test.go`: `TestDEXParser_ValidVersions`, `TestDEXParser_ULEB128_OverflowAndBoundsGuard` | Multi-dex APKs (`classes.dex`, `classes2.dex`), D8 compiler fixtures | Extracts string pools and identifies hardcoded URLs, IP addresses, API endpoints, and cloud keys. Bounded ULEB128 parsing. |
| **Signing Certificate Analysis** | Implemented and tested | `pkg/apk` | `felix apk --analyze <app.apk>` | `pkg/apk/artifact_test.go`: `TestArtifact_EndToEndSyntheticAPK` | Synthetic APKs with v1 and v2 signature schemes | Extracts certificate subject, issuer, validity period, and identifies self-signed certificates. |
| **Mobile Security Dossier Output** | Implemented and tested | `pkg/apk` | `felix apk --report <app.apk>`, `felix scan <app.apk> --export mobile_audit.html` | `pkg/apk/mobile_report_test.go`: `TestMobileReport_ValidGeneration`, `TestMobileReport_OfflineSelfContained` | Standalone HTML mobile report generation tests | Generates self-contained, responsive `mobile_audit.html` with zero external CDN dependencies. |
| **Dynamic / Runtime Analysis** | Not supported | N/A | None | Explicit non-goal | None | **Strictly static analysis.** Felix does **not** spawn emulators, execute APK bytecode, attach Frida hooks, or intercept runtime traffic. |
| **Android App Bundle (AAB)** | Not supported directly | N/A | None | Documented prerequisite | None | Felix does not parse `.aab` archives directly. Operators must convert AAB to APK via Google `bundletool` prior to intake. |

---

### F. Reporting & Output Formats

| Format / Generator | Support Level | Implementation Package | Primary CLI Entrypoint | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Pure Black HTML Report** | Implemented and tested | `pkg/report` | `felix scan --export report.html`, `felix report <json> --html <html_file>` | `pkg/report/report_test.go`: `TestHTMLReport_AllSectionsPopulated`; `test`: `TestReportingIntegrity_AllFormatsExported` | Mock assessment findings and attack surface graphs | `#000000` base palette, responsive, embedded vanilla JavaScript/CSS, zero external CDN requests, client-side search and filtering. |
| **Structured JSON** | Implemented and tested | `pkg/report` | `felix scan --json report.json`, `felix report <json> --json <json_file>` | `pkg/report/report_test.go`: `TestJSONReport_ValidOutput`; `pkg/report/cloud_database_reporting_test.go`: `TestScenario12_JSONOutputParsesAndPreservesValues` | In-memory report models and JSON schema validators | Machine-readable, deterministic JSON output. Preserves full evidence structures, timestamps, and confidence scores. |
| **OASIS SARIF 2.1.0** | Implemented and tested | `pkg/report` | `felix scan --sarif report.sarif`, `felix report <json> --sarif <sarif_file>` | `pkg/report/sarif_test.go`: `TestSARIF_StructuralValidityAndSchema`, `TestSARIF_RuleDeduplication` | Synthetic multi-finding reports validated against official SARIF schema | Fully compatible with GitHub Code Scanning, GitLab SAST/DAST, and Azure DevOps. Deduplicates rules; scrubs sensitive tokens. |
| **Commercial Report 2.0 (Executive Dossier)** | Implemented and tested | `pkg/report` | `felix report <json> --commercial <html_file>` | `pkg/report/commercial_test.go`: `TestCommercialReport_1_VerifiedFindingAppearsInVerifiedFindings`, `TestCommercialReport_20_AllEightSectionsPresentAndPopulated` | Comprehensive multi-provider enterprise assessment fixtures | Generates professional client deliverables across 8 canonical sections (Executive Summary, Scope, Attack Surface, Risk, Verified Findings, Detected Findings, Observations, Appendix). |
| **PoE Reproduction Scripts** | Implemented and tested | `pkg/report` | `felix report reproduce <json>` | `pkg/report/reproduce_test.go`: `TestGenerateReproductionScript_BashSyntax` | Verified finding fixtures with evidence payloads | Generates sanitized, non-destructive `curl` and Python reproduction scripts for verified findings. Mutating commands excluded. |
| **Report Integrity Validation** | Implemented and tested | `pkg/report` | Built into all report generation paths (`ValidateReportIntegrity`) | `pkg/report/validate_test.go`: `TestValidateReportIntegrity` | Mismatched finding count fixtures, invalid severities | Strictly enforces structural invariants: `TotalFindings == len(Findings)` and severity counts match finding arrays. |
| **PDF Generation** | Partially supported | `pkg/report` | Print to PDF via Browser | Documented in `LIMITATIONS.md` and `USAGE.md` | CSS `@media print` print-stylesheet testing | **No native PDF generation engine.** PDF export is achieved via browser "Print to PDF" using embedded `@media print` rules. |

---

### G. Continuous Monitoring, Drift Detection & Correlation

| Capability / Workflow | Support Level | Implementation Package | Primary CLI Entrypoint | Automated Test Evidence | Verification Fixture Type | Operational Bounds & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **API Surface Snapshotting** | Implemented and tested | `pkg/monitor` | `felix monitor snapshot --target <url>` | `pkg/monitor/store_test.go`: `TestSnapshotStore_PersistenceAcrossRestart` | In-memory and local disk JSON snapshot repositories | Captures point-in-time endpoint topology, parameter shapes, documentation status, and reachability. |
| **Surface Drift Calculation** | Implemented and tested | `pkg/monitor` | `felix monitor diff` (canonical alias: `felix monitor check`) | `pkg/monitor/drift_test.go`: `TestDriftComparator_NewUndocumentedRoute`; `cmd/felix`: `TestMonitorCmd_CheckAliasEquivalence` | Baseline vs current snapshot delta fixtures | Identifies added routes, removed routes, method changes, parameter shape modifications, and public exposure deltas. |
| **HMAC-SHA256 Webhook Delivery** | Implemented and tested | `pkg/monitor`, `pkg/notify` | `felix monitor snapshot --notify` | `pkg/monitor/notifier_test.go`: `TestNotifier_ValidSlackPayload`, `TestNotifier_SecretCanaryZeroLeakage` | Mock Slack, Discord, and Teams webhook listener servers | Delivers tamper-proof notifications with HMAC-SHA256 signatures. Enforces SSRF destination blocks on webhook URLs. |
| **Attack-Path DAG Traversal** | Implemented and tested | `pkg/correlation` | `felix scan` (Autonomous during correlation) | `pkg/correlation/multihop_test.go`: `TestGraph_ThreeNodePath`, `TestTraversal_MinPathLengthConfig` | Synthetic multi-node directed acyclic graphs | Traces attack paths (3+ hops) from perimeter entry points to critical terminal impact assets. Cycles safely terminated. |
| **Compound Risk Escalation** | Implemented and tested | `pkg/correlation` | `felix scan` (Autonomous during correlation) | `pkg/correlation/risk_test.go`: `TestRisk_Escalation_Medium40_Low20_Low20`, `TestRisk_MaxCapAt100` | Chain fixtures with varied finding severities and edge confidences | Evaluates compound risk (0–100) along verified attack paths. Candidate/unverified paths are strictly capped and isolated. |
| **Remediation Bottleneck Synthesizer** | Implemented and tested | `pkg/correlation` | `felix scan` (Autonomous during correlation) | `pkg/correlation/bottleneck_test.go`: `TestBottleneckSolver_01_SinglePathUniqueBottleneck`, `TestBottleneckSolver_04_MinCutMultipleElements` | Multi-path graphs with shared intermediate vulnerability nodes | Solves minimum-cut problem to identify the single remediation choke point that disrupts the maximum number of attack paths. |
| **Resident Cloud Daemon** | Not supported | N/A | None | Explicit non-goal | None | Felix does **not** run as a persistent background daemon or cloud service. Monitoring workflows are operator-triggered via CLI or cron. |

---

### H. Platform Support, Packaging & Operating Systems

| Operating System | Architecture | Binary Format | Support Level | Verification Status | Artifact & Package Test Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows** | x86_64 (`amd64`) | PE/COFF (`felix.exe`) | Implemented and tested | **Native Runtime Verified** | Local Windows host: `go test ./...` passes (37 packages, 386s); full CLI build and execution tested natively. |
| **Linux (Debian, Ubuntu, Kali)** | x86_64 (`amd64`) | ELF (`/usr/bin/felix`) | Partially supported | **Cross-Compiled & Package Verified** | `scripts/packaging`: `felix_2.0.0_amd64.deb` generated and structure-validated; GitHub Actions CI (`ubuntu-latest`) tested; native host testing pending. |
| **Linux (Debian, Ubuntu, Kali)** | ARM64 (`aarch64`) | ELF (`/usr/bin/felix`) | Partially supported | **Cross-Compiled & Package Verified** | `scripts/packaging`: `felix_2.0.0_arm64.deb` generated and structure-validated; cross-compiled; native host testing pending. |
| **Linux (Generic Tarball)** | x86_64 (`amd64`) | ELF (`felix`) | Partially supported | **Cross-Compiled & Package Verified** | `scripts/packaging/archive_test.go`: `TestArchive_IntegrityAndChecksums` validates tarball structure; native host testing pending. |
| **Linux (Generic Tarball)** | ARM64 (`aarch64`) | ELF (`felix`) | Partially supported | **Cross-Compiled & Package Verified** | `scripts/packaging/archive_test.go`: `TestArchive_IntegrityAndChecksums`; native host testing pending. |
| **macOS (Apple Silicon)** | ARM64 (`arm64`) | Mach-O (`felix`) | Partially supported | **Cross-Compiled & Package Verified** | Cross-compiled Mach-O binary; Homebrew formula (`felix.rb`) generated; native host testing pending. |
| **macOS (Intel)** | x86_64 (`amd64`) | Mach-O (`felix`) | Partially supported | **Cross-Compiled & Package Verified** | Cross-compiled Mach-O binary; archive packaging verified; native host testing pending. |
| **Atomic Self-Updater** | Cross-platform | Native replacement | Implemented and tested | **Fixture/mock validated** | `pkg/update/updater_test.go`: `TestReplace_AtomicSwapRollback`, `TestDownload_ChecksumVerification` | `felix update` (options: `--check`, `--dry-run`, `--version`, `--force`). Atomically replaces executable binary; verifies SHA-256 digests; safely rolls back on errors. |

---

## 3. Controlled Fixture Testing Strategy

To guarantee deterministic quality without violating legal or ethical boundaries, Felix maintains strict fixture isolation:

1. **Network Isolation in CI:** No automated test in the repository sends requests to third-party servers, live public cloud providers, or unapproved internet targets.
2. **Controlled HTTP Mock Servers:** All cloud, BaaS, API, and web vulnerability tests execute against local `net/http/httptest.Server` instances running on loopback interfaces.
3. **Synthetic Protocol Sockets:** Database protocol checks (MongoDB, Redis, PostgreSQL, MySQL) are tested against in-process Go TCP listener sockets emulating wire-level protocol exchanges.
4. **Synthetic Data Provenance:** Test data is tagged with `PROVENANCE_FIXTURE` or `PROVENANCE_MOCK` to prevent test results from contaminating live assessment records.
5. **Deterministic Seed Stability:** All risk calculations, entropy determinations, and graph algorithms use stable sort orders and deterministic hashing to guarantee identical results across platforms.

---

## 4. Security, Scope Enforcement & Authorization Boundaries

### Scope Enforcement & SSRF Defense

Felix strictly implements defensive boundaries to protect operator safety and target infrastructure:

- **Hostname & Subdomain Scoping:** Requests outside approved scopes (`same-origin`, `subdomains`, or explicit allowlists) are rejected before network transmission.
- **Safe Socket Dialer (`pkg/crawler/safe_dialer.go`):** Blocks connections to private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv6 loopback (`::1`), link-local addresses (`169.254.0.0/16`), and AWS/cloud metadata services (`169.254.169.254`). Operators auditing internal systems must explicitly pass `--allow-private` or `--allow-loopback`.
- **Redirect Scope Enforcement:** When an HTTP redirect leads to an out-of-scope or private target, the crawler terminates the redirect chain and logs the event as negative evidence.

### Non-Destructive Probing Guarantees & Caveats

- **Read-Oriented Probing Methods:** Default discovery and probing paths use strictly read-oriented HTTP methods (`GET`, `HEAD`, `OPTIONS`). Mutating verbs (`POST`, `PUT`, `DELETE`, `PATCH`) are excluded from automated probing.
- **Remote Side-Effect Caveat:** While read-oriented methods (`HEAD`, `OPTIONS`, `GET`) are non-mutating according to RFC specifications, **they do not guarantee that every remote server or bespoke backend implementation is completely free of side effects**. Vulnerable, non-compliant, or poorly architected target applications may trigger state transitions, queue jobs, or invalidate sessions on `GET` requests. Operators must assess staging environments or ensure authorization covers safe probing.
- **No Destructive Exploits:** Felix does not attempt active SQL injection fuzzing, remote code execution payloads, administrative password brute-forcing, or data deletion.
- **Fail-Closed Verification:** Network errors, timeouts, or ambiguous response formats are classified as `INCONCLUSIVE` or `NOT_VERIFIED`, never fabricated as positive vulnerabilities.

### Secret Redaction & Sanitization

- **Zero Secret Value Leakage:** Discovered tokens, API keys, passwords, and authorization headers are immediately sanitized before entering report data models, logs, or JSON/SARIF output.
- **Safe Proof-of-Exploitation:** Reproduction scripts generated by `felix report reproduce` omit live secret strings, referencing environment variables instead.

---

## 5. Explicit Non-Goals & Architectural Boundaries

The following capabilities are explicitly **outside product scope** and are not implemented:

1. **Destructive Exploitation:** Felix reports verifiable exposure; it does not perform automated exploitation, account takeover, or data exfiltration.
2. **Embedded Browser Runtimes:** Felix does not bundle Chromium, Node.js, or Playwright. (An optional driver can invoke an external, operator-provided browser executable if present, but is disabled by default).
3. **Direct Binary Wire Database Exploitation:** Felix conducts protocol-level reachability probes and audits HTTP management APIs; it does not perform raw database table dumps or SQL protocol fuzzing.
4. **Android Dynamic / Runtime Instrumentation:** Felix performs static inspection of APK packages; it does not run emulators, attach Frida hooks, or perform dynamic memory tracing.
5. **Continuous Resident Daemons:** Felix operates as an on-demand CLI tool; it does not install persistent background cloud services or resident daemons.
6. **Checkbox Compliance Questionnaires:** Felix reports empirical security evidence, not subjective questionnaire assessments (e.g. SOC 2 or ISO 27001 policy attestations).

---

## 6. Open Release-Security Blockers (Phase 12.10 Gate)

Prior to formal release publication under Phase 12.10, the following security item remains tracked as an **unresolved release blocker**:

> [!CAUTION]
> **Debian APT OpenPGP Private Signing Key Exposure:**
> The private signing key `scripts/packaging/keys/apt-signing-key.priv.asc` was committed to repository history (commit `f8f2f59d90fb3d02a4664c357e87f7528d3677ab`).
>
> **Current Status:**
> - The release packaging script `scripts/packaging/main.go` has been patched to reject local repository keys and requires secrets injected via environment variables (`FELIX_APT_SIGNING_KEY`).
> - The compromised key fingerprint `8ABF68D0253A139577CA06E7154B088FE357A53D` is permanently hardcoded for rejection across all packaging and update verification paths.
> - Detached RFC 4880 OpenPGP signing (`SHA256SUMS.asc`) and update verification have been implemented and verified across 16 security test scenarios.
> - However, the committed key material has **not yet been formally revoked, rotated with a published transition notice, or scrubbed from Git history**.
> - External APT repository distribution remains paused. Operators on Debian/Ubuntu/Kali are advised to install via direct `.deb` package download with SHA-256 digest and detached OpenPGP signature verification once rotated keys are active.
> - Final remediation, key revocation, and trust migration are explicitly tracked in **Phase 12.10 (Release Decision)**.
