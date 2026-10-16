# FELIX — Phase 2.2: Access Verification Completion Report

**Repository:** `C:\Jothish\felix`  
**GitHub Repository:** `jothish-blip/felix`  
**Branch:** `main`  
**Phase ID:** Phase 2.2 — Access Verification  
**Predecessor:** Phase 2.1 — Universal Cloud, Database and Storage Intelligence  
**Status:** PASS WITH DOCUMENTED LIMITATIONS  
**Date:** 2026-10-16  

---

## 1. Executive Summary

Phase 2.2 (Access Verification) builds directly upon the Phase 2.1 universal service discovery foundation across all 16 target database, backend, Firebase, and object storage services. The primary objective is to evaluate and distinguish empirically between service reachability, authentication challenges, authenticated vs unauthenticated access, and bounded read/write permissions on specific, authorized resources.

Crucially, Phase 2.2 eliminates conflation between connectivity and vulnerability:
- A network ping or protocol handshake (`PONG`, MySQL handshake, HTTP 200 on root) is never reported as proof of unrestricted data access.
- Every read verification operation targets a known, explicitly configured synthetic test resource and never enumerates keys, collections, tables, buckets, or documents.
- Controlled canary write verification is disabled by default and requires satisfaction of all 8 mandatory safety guardrails.
- Credentials and sensitive tokens are strictly redacted and never leaked across origin redirects, logs, findings, or error traces.

All 21 Go packages in the FELIX repository compile cleanly, pass `go vet`, and pass all unit and regression tests (including all 27 required Phase 2.2 test scenarios and all 16 target providers).

---

## 2. Work Packages Completed

| Work Package | Title | Status | Description |
|---|---|---|---|
| **WP 2.2.1** | Access Model and Contracts | **COMPLETED** | Created `pkg/cloud/access_types.go` defining controlled vocabulary (`AccessStatus`, `AccessDecision`, `AuthenticationContext`, `OperationTested`, `ErrorClassification`), `CredentialProfile` with redaction, `TestResourceConfig`, `AccessVerificationRecord`, and validation invariants. |
| **WP 2.2.2** | Shared Verification Engine | **COMPLETED** | Implemented `AccessVerificationEngine` in `pkg/cloud/access_engine.go` providing pre-transmission scope/exclusion checks, concurrency control, safe error classification, timeout/cancellation handling, and finding normalization. |
| **WP 2.2.3** | Database and Admin Verifiers | **COMPLETED** | Implemented `pkg/cloud/verifier_databases.go` (Elasticsearch, MongoDB, Redis, PostgreSQL, MySQL) and `pkg/cloud/verifier_admin.go` (Mongo Express) with bounded, non-destructive read checks on configured test resources. |
| **WP 2.2.4** | Backend and Application Data Verifiers | **COMPLETED** | Implemented `pkg/cloud/verifier_backend.go` (Supabase, PostgREST, Hasura, Prisma) and `pkg/cloud/verifier_firebase.go` (Firebase RTDB, Cloud Firestore) respecting ORM boundaries and RLS policies. |
| **WP 2.2.5** | Object Storage Verifiers | **COMPLETED** | Implemented `pkg/cloud/verifier_storage.go` (AWS S3, Azure Blob Storage, Google Cloud Storage, MinIO) with synthetic object HEAD probes and zero enumeration. |
| **WP 2.2.6** | Credential Safety and Read Boundaries | **COMPLETED** | Enforced credential masking (`***REDACTED***`), origin-boundary checks, and strict resource localization so denials and allowances are never generalized across entire clusters. |
| **WP 2.2.7** | Optional Canary Framework | **COMPLETED** | Implemented `pkg/cloud/canary.go` enforcing all 8 mandatory conditions (explicit user opt-in, run authorization, scope check, supported isolated canary, test resource, no-overwrite guarantee, verified non-destructive cleanup, least-privilege identity). |
| **WP 2.2.8** | Integration, Tests, and Documentation | **COMPLETED** | Integrated with `Detector.Audit` and created comprehensive test suite in `pkg/cloud/access_test.go` covering all 27 required scenarios and all 16 target services. |
| **WP 2.2.9** | Final Acceptance Gate | **COMPLETED** | Conducted full regression suite, `go vet`, build verification, and clean git state audit. |

---

## 3. Access Model and Normalized Outcome Definitions

The access verification model enforces a controlled vocabulary in `pkg/cloud/access_types.go`:

### Controlled Access Statuses (`AccessStatus`)
- `SERVICE_DETECTED`: Empirical detection of the service technology without verifying reachability.
- `SERVICE_REACHABLE`: Network-level reachability established (TCP connection, protocol handshake, HTTP ping). Not a security finding.
- `AUTH_CHALLENGED`: Service explicitly challenged or required authentication (HTTP 401/403, `-NOAUTH`, protocol handshake rejection).
- `UNAUTHENTICATED_ACCESS`: Verified unauthenticated access to the tested endpoint or resource.
- `AUTHENTICATED_ACCESS`: Verified access using explicitly supplied, authorized credentials.
- `READ_ALLOWED`: Read access permitted for the specifically tested resource.
- `READ_DENIED`: Read access explicitly denied or restricted by security rules/policies for the tested resource.
- `INCONCLUSIVE`: Response was ambiguous, truncated, or inconclusive.
- `SKIPPED`: Verification skipped due to scope rules, absence of authorization, or unsupported operations.
- `WRITE_VERIFIED`: Controlled canary write succeeded under explicit authorization.
- `WRITE_DENIED`: Controlled canary write was denied for the canary resource.

### Model Invariants Enforced by `Validate()`
1. Target and Technology must be non-empty.
2. Unauthenticated data read (`READ_ALLOWED` under `OpBoundedRead`) cannot be claimed without an explicit, non-empty `ResourceScope`.
3. Service reachability alone is never marked `FindingSuitable`.
4. Protocol probes or root metadata reads cannot claim application data read status.
5. Skipped or out-of-scope targets can never have an `ALLOWED` decision.

---

## 4. Provider-by-Provider Implementation Status (16 Targets)

| # | Target Service | Verifier Function | Unauthenticated Check | Authenticated Check | Bounded Read Resource | Canary Write | Status |
|---|---|---|---|---|---|---|---|
| 1 | **Elasticsearch** | `VerifyElasticsearchAccess` | Metadata `GET /` | Basic / Bearer Auth | `GET /<test_index>/_search?size=1` | Unsupported | **Verified by Tests** |
| 2 | **MongoDB** | `VerifyMongoDBAccess` | Wire `isMaster` | Protocol credentials | Bounded test collection read | Unsupported | **Verified by Tests** |
| 3 | **Redis** | `VerifyRedisAccess` | `PING` (PONG vs -NOAUTH) | `AUTH <secret>` | `GET <test_key>` | Supported (opt-in NX) | **Verified by Tests** |
| 4 | **PostgreSQL** | `VerifyPostgreSQLAccess` | `SSLRequest` + Startup | User/pass authentication | Minimal table read | Unsupported | **Verified by Tests** |
| 5 | **MySQL** | `VerifyMySQLAccess` | Handshake pkt (proto 10) | Handshake response auth | Minimal table read | Unsupported | **Verified by Tests** |
| 6 | **Mongo Express**| `VerifyMongoExpressAccess` | Web console `GET /` | HTTP Basic Auth | Bounded status check | Unsupported | **Verified by Tests** |
| 7 | **Supabase** | `VerifySupabaseAccess` | `GET /rest/v1/` | Scoped API key / Bearer | `GET /rest/v1/<test_table>?limit=1` | Unsupported | **Verified by Tests** |
| 8 | **PostgREST** | `VerifyPostgRESTAccess` | Root OpenAPI spec | JWT Authorization | `GET /<resource>?limit=1` | Unsupported | **Verified by Tests** |
| 9 | **Hasura** | `VerifyHasuraAccess` | Root introspection / health | Least-privilege Bearer / `X-Hasura-Role` (admin secret only if configured) | Bounded test query | Unsupported | **Verified by Tests** |
| 10| **Prisma** | `VerifyPrismaAccess` | Architectural boundary | Application endpoint only | Application test endpoint | Unsupported | **Verified by Tests (Explicit Architecture Boundary)** |
| 11| **Firebase RTDB**| `VerifyFirebaseRTDBAccess`| Bounded test path | `Authorization: Bearer <secret>` header (no query param token leak) | `GET /<test_path>.json?limitToFirst=1` | Unsupported | **Verified by Tests** |
| 12| **Firestore** | `VerifyFirestoreAccess` | Database root metadata | Bearer token | Bounded test document read | Unsupported | **Verified by Tests** |
| 13| **AWS S3** | `VerifyAWSS3Access` | Root `HEAD /` | AWS Auth headers | `HEAD /<test-object>` | Supported (opt-in isolated) | **Verified by Tests** |
| 14| **Azure Blob** | `VerifyAzureBlobAccess` | Container `HEAD /` | SAS token / Shared Key | `HEAD /<container>/<test-blob>` | Unsupported | **Verified by Tests** |
| 15| **GCS** | `VerifyGCSAccess` | Bucket `HEAD /` | Bearer token | `HEAD /<bucket>/<test-object>` | Unsupported | **Verified by Tests** |
| 16| **MinIO** | `VerifyMinIOAccess` | `/minio/health/live` | S3 credentials | `HEAD /<bucket>/<test-object>` | Supported (opt-in isolated) | **Verified by Tests** |

---

## 5. Authentication and Credential Safety

- **Credential Profiles:** Defined in `CredentialProfile` with unexported secret fields (`Secret`, `Headers`).
- **Sanitized Redaction:** Calling `Redacted()` masks secrets and sensitive headers as `***REDACTED***`. `RedactSensitiveString` sanitizes error strings, diagnostic logs, and limitations.
- **Header-Based Transmission:** Firebase RTDB credentials are transmitted exclusively via `Authorization: Bearer <secret>` HTTP headers rather than `?auth=` query parameters to prevent leakage in URL logs, error messages, and network traces.
- **Finding Isolation:** Credential values are strictly prevented from appearing in findings, logs, error strings, or completion reports (verified in Scenarios 18 and Audit Regression).
- **Cross-Origin Boundary:** Redirects to different origins immediately strip `Authorization`, `apikey`, `x-hasura-admin-secret`, and `x-api-key` headers (`CheckRedirect` in `pkg/cloud/client.go` blocks cross-host following, verified in Scenario 14).
- **No Brute-Force:** Credential spraying, guessing, and retrying are strictly excluded.

---

## 6. Read-Boundary Verification Behavior

- **Explicit Resources:** Read tests target known, synthetic resources (e.g. `test_index`, `test_key`, `test_table`, `test-object.txt`, `test_path`).
- **Zero Enumeration:** Default verification NEVER executes enumerative requests (`KEYS *`, `SCAN`, `?comp=list`, `?max-keys`, `/documents` listing are strictly forbidden and verified in Scenario 19).
- **Strict Scope Localization:** An authorization decision for one resource is strictly localized and never generalized to the entire service or cluster (verified in Scenario 25).

---

## 7. Canary Write Support and Default-Disabled Guardrails

Write verification is disabled by default (`AllowWriteVerification: false`) and requires satisfaction of all 8 mandatory conditions:
1. Explicit user opt-in (`AllowWriteVerification = true` and `canary.Enabled = true`).
2. Explicit run authorization (`canary.ExplicitlyAuthorized = true`).
3. Target and resource verified within authorized assessment scope and not excluded.
4. Explicit test resource configured (root/wildcard targets rejected).
5. Provider supports safe, isolated canary operations (Redis, AWS S3, MinIO only).
6. No-overwrite guarantee enabled (`PreventOverwriteCheck = true`).
7. Non-destructive cleanup behavior verified and permitted (`AllowCleanup = true`).
8. Configured identity confirmed as least-privilege (`Role == "least_privilege_test"` and `IdentityLeastPrivilegeVerified = true`).

Concrete canary operations are implemented with strict atomic lifecycles:
- **Redis (`RedisCanaryOperation`):** Evaluates `EXISTS <canary_key>` pre-check (fails if key exists), executes `SET <canary_key> <val> NX EX 60`, verifies `GET <canary_key>`, and executes non-destructive `DEL <canary_key>`.
- **S3 / MinIO (`S3CanaryOperation`):** Evaluates `HEAD /<canary_object>` pre-check (fails if object exists), executes `PUT /<canary_object>` with `If-None-Match: *`, verifies `HEAD /<canary_object>`, and performs non-destructive `DELETE /<canary_object>`.

If any condition or pre-check fails, write testing is safely skipped or aborted with an explicit limitation recorded. In Scenario 22, failed canary pre-check verification does not trigger destructive cleanup.

---

## 8. Scope, SSRF, Transport, and Runtime Safeguards

- **SSRF & Scope Enforcement:** All TCP and HTTP verifier operations route through `Client.SafeDialContext` and `Client.Do`. Scope (`isAllowed`) and exclusion (`isExcluded`) are evaluated before any network transmission (verified in Scenarios 12 and 13).
- **TLS Validation:** Strict TLS validation is enforced; invalid certificates are not bypassed (verified in Scenario 15).
- **Bounded Responses:** `io.LimitReader` limits response sizes to `MaxResponseSize` (verified in Scenario 16).
- **Rate-Limiting Safety:** HTTP 429 immediately returns `ErrRateLimited` without hammering targets (verified in Scenario 17).
- **Cancellation:** Context cancellation promptly terminates connections and in-flight operations (verified in Scenario 27).

---

## 9. Findings and Evidence Integration

- Service reachability (`SERVICE_REACHABLE`) and informational metadata queries do not generate vulnerability findings.
- **Severity Calibration:** Informational metadata exposure (e.g. cluster name, public version banner) is calibrated to `SeverityInfo`. Confirmed unauthenticated application data read access on an explicit resource (`READ_ALLOWED` on `BOUNDED_RESOURCE_READ`) generates `SeverityHigh`.
- **Resource-Scoped Deduplication:** Deduplication utilizes deterministic SHA-256 fingerprints via `GenerateScopedFingerprint(target, resourceScope, tech, title)` ensuring that distinct resources (e.g. tables `users` vs `orders`) produce distinct findings while preventing duplicate findings for repeated evaluations of the same resource.

---

## 10. Automated Tests Executed and Outcomes

### Test Execution Commands
```powershell
go test -v -count=1 -run "TestAccess|TestDatabaseProtocolHandshake|TestFirebaseRTDB|TestHasura|TestCanary|TestFindings" ./pkg/cloud
go test -count=1 ./pkg/cloud/... ./pkg/discovery/... ./pkg/assessment/... ./cmd/...
go test -count=1 ./cmd/... ./pkg/...
go vet ./cmd/... ./pkg/...
go build -o bin/felix.exe ./cmd/felix
git diff --check
git status -- benchmarks/results/latest.json
```

### Test Outcomes
- `TestAccessModel_ValidationAndInvariants`: **PASS**
- `TestCredentialProfile_Redaction`: **PASS**
- `TestAccessVerification_All27Scenarios`: **PASS (All 27 subtests passed)**
  1. `01_InScope_NoAuth_Configured`: **PASS**
  2. `02_InScope_Auth_Challenge`: **PASS**
  3. `03_Valid_Configured_Credentials_Accepted`: **PASS**
  4. `04_Invalid_Credentials_Rejected`: **PASS**
  5. `05_Authenticated_Identity_Denied_Resource_Access`: **PASS**
  6. `06_Unauthenticated_Read_Permitted_Synthetic_Resource`: **PASS**
  7. `07_Authenticated_Read_Permitted_Synthetic_Resource`: **PASS**
  8. `08_Service_Reachable_Data_Access_Unverified`: **PASS**
  9. `09_Timeout_Or_Unreachable_Target`: **PASS**
  10. `10_Malformed_Provider_Response`: **PASS**
  11. `11_Unsupported_Verification_Operation`: **PASS**
  12. `12_OutOfScope_Target_Blocked`: **PASS**
  13. `13_Excluded_Target_Blocked`: **PASS**
  14. `14_Redirect_Cross_Origin_Credentials_Stripped`: **PASS**
  15. `15_TLS_Verification_Failure_Not_Bypassed`: **PASS**
  16. `16_Response_Size_Limit_Enforced`: **PASS**
  17. `17_RateLimit_Responses_Handled`: **PASS**
  18. `18_Credentials_Absent_From_Findings_And_Records`: **PASS**
  19. `19_No_Default_Enumeration`: **PASS**
  20. `20_No_Write_Request_Without_Authorization`: **PASS**
  21. `21_Authorized_Write_Isolated_To_Canary`: **PASS**
  22. `22_Failed_Canary_Does_Not_Trigger_Destructive_Cleanup`: **PASS**
  23. `23_Protocol_Handshake_Does_Not_Imply_Public_Access`: **PASS**
  24. `24_Successful_Metadata_Does_Not_Imply_Data_Access`: **PASS**
  25. `25_Denied_Read_Not_Misclassified_As_Global_Protection`: **PASS**
  26. `26_Multiple_Detections_No_Duplicate_Findings`: **PASS**
  27. `27_Cancellation_Releases_Resources`: **PASS**
- `TestAccessVerification_All16Providers`: **PASS (All 16 providers passed)**
- `TestFirebaseRTDB_CredentialSafetyAndRedaction`: **PASS**
- `TestHasura_LeastPrivilegeIdentityAndErrorHandling`: **PASS**
- `TestCanaryWrite_StrictGuardrailsAndOverwrites`: **PASS**
- `TestFindings_DeduplicationAndSeverityCalibration`: **PASS**
- `TestDatabaseProtocolHandshake_EmpiricalVerification`: **PASS**
  - `PostgreSQL_MD5_Challenge`: **PASS**
  - `MySQL_Handshake_Access_Denied`: **PASS**
  - `MySQL_Handshake_Reachability_Only`: **PASS**
  - `MySQL_Handshake_Anonymous_OK`: **PASS**
- `TestCanary_Redis_LifecycleSafety`: **PASS**
  - `Redis_PreExistingResource`: **PASS**
  - `Redis_FailedCreation`: **PASS**
  - `Redis_FailedVerification`: **PASS**
  - `Redis_ConcurrentReplacement_OwnershipMismatch`: **PASS**
  - `Redis_RepeatedCleanup`: **PASS**
- `TestCanary_S3_LifecycleSafety`: **PASS**
  - `S3_PreExistingResource`: **PASS**
  - `S3_FailedCreation`: **PASS**
  - `S3_FailedVerification_ETagMismatch`: **PASS**
  - `S3_ConcurrentReplacement_CleanupRefused`: **PASS**
  - `S3_RepeatedCleanup`: **PASS**
- `TestDatabaseBoundedQueries_EmpiricalVerification`: **PASS**
  - `MongoDB_BoundedRead_Denied`: **PASS**
  - `PostgreSQL_BoundedRead_Denied`: **PASS**
  - `MySQL_BoundedRead_Denied`: **PASS**
- Full Repository Test Suite (21 packages): **PASS (All 21 packages passed)**
- `go vet ./cmd/... ./pkg/...`: **PASS (0 warnings)**
- `go build -o bin/felix.exe ./cmd/felix`: **PASS**
- `benchmarks/results/latest.json`: **Pristine, untouched**

---

## 11. Known Limitations and Unsupported Scenarios

1. **Prisma Network Probing:** Prisma is an internal ORM layer embedded in application code. It does not expose a standalone public database listener. Black-box network access verification for Prisma is explicitly marked `UNSUPPORTED` / `SKIPPED` unless an authorized application endpoint is supplied.
2. **Canary Write Scope:** Canary write verification is supported only for Redis, AWS S3, and MinIO where non-destructive isolated canaries with guaranteed pre-check checks are reliable. Complex relational database DDL/DML canary writes remain unsupported to protect database integrity.
3. **Automated Test Provider Fixtures:** Automated tests utilize deterministic TCP listeners and HTTP mock fixtures rather than connecting to live, billable, third-party public cloud services.

---

## 12. Regression Results for Phase 1 and Phase 2.1

- **Scope & SSRF Enforcement:** All Phase 1.1 safety guarantees remain intact.
- **Common Data Model:** All asset and finding schemas remain backward compatible.
- **Phase 2.1 Service Discovery:** All 16 service detection paths and discovery test cases pass with zero regressions.
- **Benchmark Baseline:** `benchmarks/results/latest.json` remains completely unmodified.

---

## 13. Changed Files and Rationale

| File Path | Nature of Change | Rationale |
|---|---|---|
| `pkg/cloud/access_types.go` | Modified | Core access verification model, controlled status vocabulary, credential profiles, validation invariants, `RedactSensitiveString`, `IdentityLeastPrivilegeVerified` on `CanaryConfig`, `GenerateScopedFingerprint`, calibrated finding severity. |
| `pkg/cloud/canary.go` | Modified | Concrete `RedisCanaryOperation` and `S3CanaryOperation` with atomic pre-check and non-destructive cleanup; enforces `IdentityLeastPrivilegeVerified`. |
| `pkg/cloud/verifier_databases.go` | Modified | Group A database verifiers; empirical MySQL handshake packet and response (0x00 OK vs 0xFF Error vs 0xFE Switch) verification; PostgreSQL `AuthenticationRequest` type inspection; client error redaction. |
| `pkg/cloud/verifier_admin.go` | New file | Group B database administration interface access verifier (Mongo Express). |
| `pkg/cloud/verifier_backend.go` | Modified | Group C backend verifiers; Hasura least-privilege Bearer/role verification, rejection of admin secret defaulting, classification of GraphQL errors as `READ_DENIED`. |
| `pkg/cloud/verifier_firebase.go` | Modified | Group D Firebase RTDB verifier transmitting credentials via `Authorization: Bearer <secret>` header instead of query parameters; credential masking. |
| `pkg/cloud/verifier_storage.go` | New file | Group E cloud/object storage access verifiers (AWS S3, Azure Blob, GCS, MinIO). |
| `pkg/cloud/access_engine.go` | Modified | Shared access engine dispatching verification and executing concrete canary lifecycle operations. |
| `pkg/cloud/client.go` | Modified | Redirect safety; explicitly stripping sensitive authentication and API key headers across cross-origin redirects. |
| `pkg/cloud/detector.go` | Modified | Add `accessEngine` field and integrate access verification into `AuditResult`. |
| `pkg/cloud/access_test.go` | Modified | Comprehensive unit and audit regression test suites covering model invariants, 27 core scenarios, all 16 providers, Firebase credential safety, Hasura least-privilege, canary guardrails, finding deduplication, and database handshake empirical verification. |
| `pkg/cloud/canary_audit_test.go` | New file | Concurrency and lifecycle safety regression tests for Redis and S3/MinIO canary operations (pre-existing resources, failed creation, verification failure, concurrent replacement, ownership mismatch, cleanup failure, repeated cleanup) and database bounded query empirical verification. |
| `docs/engineering/PHASE_2_2_ACCESS_VERIFICATION_COMPLETION_REPORT.md` | Modified | Formal Phase 2.2 engineering completion and audit report. |

---

## 14. Exit Gate Decision

**Final Status:** **PASS WITH DOCUMENTED LIMITATIONS**

All mandatory acceptance criteria for Phase 2.2 are satisfied:
- Empirical access status model is implemented with strict controlled vocabulary and validation.
- All 16 target services have dedicated access verification implementations and pass tests.
- Scope, exclusions, and SSRF protections are enforced prior to network transmissions.
- Credentials and tokens are redacted and protected from logs, findings, and errors.
- Read verification targets synthetic resources with zero production enumeration.
- Canary writes are disabled by default and gated by 8 strict conditions with concrete pre-checks.
- All 21 Go packages compile, vet cleanly, and pass all automated tests.

---

## 15. Security Audit and Remediation Findings

During the Phase 2.2 security audit, the implementation was evaluated against strict safety and precision criteria. The following defects were identified and remediated:

### Audit 1: Firebase RTDB Credential Leakage Prevention
- **Issue:** Query string authentication (`?auth=<token>`) can leak tokens into `net/http` error strings (e.g. `dial tcp ...: dial error in Get https://host/?auth=secret`), proxy logs, and diagnostic records.
- **Remediation:** Migrated Firebase RTDB authentication to use standard `Authorization: Bearer <secret>` HTTP headers. Implemented `RedactSensitiveString` to sanitize any token values from `record.Limitations` and error classifications. Verified by `TestFirebaseRTDB_CredentialSafetyAndRedaction`.

### Audit 2: Hasura Least-Privilege Identity Handling
- **Issue:** Relying on `x-hasura-admin-secret` by default bypasses Row-Level Security (RLS) and violates least-privilege verification. In addition, GraphQL syntax/validation errors could be misclassified.
- **Remediation:** Updated `VerifyHasuraAccess` to support least-privilege identity (`Authorization: Bearer <token>` and `X-Hasura-Role: <role>`), requiring `x-hasura-admin-secret` only if explicitly configured. GraphQL validation and permission errors are strictly classified as `READ_DENIED` rather than permitted reads. Verified by `TestHasura_LeastPrivilegeIdentityAndErrorHandling`.

### Audit 3: Empirical Database Protocol Handshakes and Bounded Queries
- **Issue:** Reachability on database ports was previously conflated with authentication challenges, and authentication was conflated with table/collection read access without executing bounded queries.
- **Remediation:**
  - **MySQL:** Implemented empirical Handshake Response packet handling. Initial Handshake Packet alone (protocol 10) confirms `SERVICE_REACHABLE`. Server ERR packet (0xFF) or AuthSwitch (0xFE) marks `AUTH_CHALLENGED`. Server OK packet (0x00) marks `UNAUTHENTICATED_ACCESS` (or `AUTHENTICATED_ACCESS`). If a test table is configured, sends `COM_QUERY` (`SELECT 1 FROM ... LIMIT 1`) to empirically confirm `READ_ALLOWED` vs `READ_DENIED`.
  - **PostgreSQL:** Implemented parsing of `AuthenticationRequest` type ('R') and auth code (0 = `AuthenticationOk` / trust authentication, >0 = authentication challenge). If a test table is configured, sends Query message ('Q') to empirically confirm `READ_ALLOWED` vs `READ_DENIED`.
  - **MongoDB:** Replaced `isMaster` metadata inspection with explicit `OP_QUERY` targeting `test.<collection>`, accurately classifying authentication requirements (code 13 `Unauthorized`) as `READ_DENIED`.
  - Verified by `TestDatabaseProtocolHandshake_EmpiricalVerification` and `TestDatabaseBoundedQueries_EmpiricalVerification`.

### Audit 4: Findings Severity Calibration and Resource-Scoped Deduplication
- **Issue:** Metadata exposure was assigned `SeverityMedium` (too high for harmless cluster banners) and finding fingerprints collided when testing different resources on the same endpoint.
- **Remediation:** Metadata exposure is calibrated to `SeverityInfo`. Introduced `GenerateScopedFingerprint` which incorporates the target, resource scope, technology, and finding title, allowing distinct tables/paths on the same host to generate independent findings without deduplication collisions. Verified by `TestFindings_DeduplicationAndSeverityCalibration`.

### Audit 5: Canary Write Concurrency, Ownership Safety, and Lifecycle Guardrails
- **Issue:** Canary cleanup previously used unconditional deletions without confirming resource ownership or protecting against concurrent replacement.
- **Remediation:**
  - **Redis:** Implemented atomic Compare-and-Delete via Lua script `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end` (with fallback to `WATCH`/`GET`/`MULTI`/`DEL`/`EXEC`). If the key does not match or was replaced concurrently, cleanup refuses to delete the foreign key and reports ownership mismatch.
  - **S3 / MinIO:** Captured created `ETag` and unique canary token on `PUT` (with `If-None-Match: *`). Prior to deletion, performs pre-cleanup `HEAD` check verifying ETag and token identity; executes conditional `DELETE` with `If-Match`. If the object was replaced by another process, cleanup aborts to prevent deleting the foreign object.
  - **Lifecycle Invariants:** Failed pre-check or failed creation prevents write and never invokes destructive cleanup. Unwritten canary operations treat cleanup as safe no-op. Repeated cleanup calls are idempotent safe no-ops.
  - Verified by `TestCanary_Redis_LifecycleSafety` and `TestCanary_S3_LifecycleSafety`.
