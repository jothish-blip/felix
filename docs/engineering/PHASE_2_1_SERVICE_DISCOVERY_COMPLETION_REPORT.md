# FELIX — Phase 2.1: Universal Cloud, Database, and Storage Service Discovery
## Final Acceptance & Engineering Completion Report

**Date:** 2026-10-16
**Status:** CLOSED — PASS WITH DOCUMENTED LIMITATIONS
**Phase:** Phase 2.1 — Universal Cloud, Database and Storage Intelligence
**Target Repository:** `jothish-blip/felix` (Branch `main`)
**Platform / Toolchain:** Windows amd64, Go 1.27.0

---

## 1. Executive Summary

Phase 2.1 implements universal, non-destructive, evidence-based service discovery across all **16 mandatory service targets** defined in the FELIX master roadmap. Every discovered service is identified through deterministic signatures, wire protocol handshakes, and bounded HTTP responses. Discovered services are ingested directly into FELIX's Common Asset Model (CAM) inventory, creating typed `Database`, `Storage`, and `Service` entities linked by verified relational edges (`RelUsesDatabase`, `RelUsesStorage`, `RelExposesService`, `RelHostsService`).

Following comprehensive safety auditing and acceptance review, the discovery engine satisfies all Phase 1 safety contracts:
- Outbound network requests and raw TCP sockets are dialed exclusively through safe transports and `crawler.NewSafeDialContext`, strictly prohibiting SSRF destinations, loopback addresses, RFC 1918 private subnets, and cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`).
- All active probes validate scope authorization (`isAllowed` and `isExcluded`) prior to connection.
- Probes enforce non-enumeration: bucket/container listing requests (`?max-keys=1`, `?comp=list`), database record retrievals, document collection iteration (`/documents`), and key searches (`/.json?shallow=true`) are prohibited during discovery.
- Service discovery findings strictly emit at `SeverityInfo`. Unauthenticated data boundary verification, canary writes, and intrusive exploit tests are strictly deferred to Phase 2.2.

---

## 2. 16-Service Target Verification & Implementation Status

| Target # | Group | Service / Technology | Implementation Path | Supporting Empirical Evidence | Documented Limitations |
|---|---|---|---|---|---|
| **1** | A | **Elasticsearch** | `ProbeElasticsearch` (`pkg/cloud/detector_databases.go`) | HTTP 200 OK root JSON (`tagline: "You Know, for Search"`, cluster/node name, version); or HTTP 401 with `Basic realm="security"` and `security_exception` | Root info confirms cluster presence; indices read permissions require Phase 2.2 verification |
| **2** | A | **MongoDB** | `ProbeMongoDB` (`pkg/cloud/detector_databases.go`) | Wire BSON `isMaster` (OP_QUERY 2004) handshake response (`"ismaster"`, `"isWritablePrimary"`); or HTTP port notice (`"trying to access MongoDB over HTTP..."`) | Wire handshake confirms active protocol; authentication challenge and collection read access require Phase 2.2 |
| **3** | A | **Redis** | `ProbeRedis` (`pkg/cloud/detector_databases.go`) | TCP `PING\r\n` -> RESP response `+PONG\r\n`, `-NOAUTH Authentication required`, or `-DENIED protected mode` | `+PONG` confirms service identity; keyspace access and data read permissions require Phase 2.2 |
| **4** | A | **PostgreSQL** | `ProbePostgreSQL` (`pkg/cloud/detector_databases.go`) | Standard `SSLRequest` packet (`\x00\x00\x00\x08\x04\xd2\x16\x2f`) -> server response byte `'S'` (SSL supported) or `'N'` | Protocol presence confirmed; server authentication policies are evaluated during connection handshake in Phase 2.2 |
| **5** | A | **MySQL** | `ProbeMySQL` (`pkg/cloud/detector_databases.go`) | Initial Handshake Packet (Protocol 10 `0x0A` + null-terminated server version); or Error Packet (`0xFF` + 1130 host restriction) | Initial Handshake confirms protocol; authentication requirements and user access policies are evaluated in Phase 2.2 |
| **6** | B | **Mongo Express** | `ProbeMongoExpress` (`pkg/cloud/detector_admin.go`) | HTML `<title>Mongo Express</title>`, links `/db/`, cookies `mongo-express`, or HTTP 401 auth challenge | UI presence confirmed; database management authentication and CRUD authorization require Phase 2.2 |
| **7** | C | **Supabase** | `probeSupabase` (`pkg/cloud/service_discovery.go`) | Hostname `*.supabase.co`, `/rest/v1/` endpoint, Kong header `sb-gateway-mode`, JWT claims (`iss: "supabase"`) | REST gateway presence confirmed; table access policies (RLS) require Phase 2.2 verification |
| **8** | C | **PostgREST** | `ProbePostgREST` (`pkg/cloud/detector_backend.go`) | Header `Range-Unit: items`, OpenAPI title `"PostgREST API"`, error codes matching `PGRST\d{3}` | Endpoint schema/error signature confirmed; table read access deferred to Phase 2.2 |
| **9** | C | **Hasura** | `ProbeHasura` (`pkg/cloud/detector_backend.go`) | `/v1/version` -> version JSON; `/v1/graphql` -> validation error; header `x-hasura-role` | Engine presence confirmed; GraphQL schema introspection and role access deferred to Phase 2.2 |
| **10** | C | **Prisma** | `AssessPrisma` (`pkg/cloud/detector_backend.go`) | Passive client bundle references (`@prisma/client`, `schema.prisma`) or leaked database errors (`P2002`) | Internal server-side ORM; black-box detection requires client bundle traces or leaked error codes |
| **11** | D | **Firebase RTDB** | `ProbeFirebaseRTDB` (`pkg/cloud/detector_firebase.go`) | Non-enumerating `HEAD /.json` -> 200 OK or 401 `"Permission denied"` | Root endpoint reachable; granular path/key read boundaries require Phase 2.2 verification |
| **12** | D | **Cloud Firestore** | `ProbeFirestore` (`pkg/cloud/detector_firebase.go`) | Non-enumerating database root metadata `/databases/(default)` -> 200 OK or 403 `PERMISSION_DENIED` | Database metadata accessible; collection-level rule coverage deferred to Phase 2.2 |
| **13** | E | **AWS S3** | `ProbeAWSS3` (`pkg/cloud/detector_storage.go`) | Non-enumerating `HEAD /`; headers `Server: AmazonS3`, `x-amz-request-id` | S3 service confirmed; object read/write permissions require Phase 2.2 verification |
| **14** | E | **Azure Blob** | `ProbeAzureBlob` (`pkg/cloud/detector_storage.go`) | Non-enumerating `HEAD /`; headers `Server: Windows-Azure-Blob`, `x-ms-request-id` | Azure container confirmed; blob permissions require Phase 2.2 verification |
| **15** | E | **Google Cloud Storage** | `ProbeGCS` (`pkg/cloud/detector_storage.go`) | Non-enumerating `HEAD /`; headers `Server: UploadServer` / `Server: GSE`, `x-goog-generation` | GCS bucket confirmed; object read permissions require Phase 2.2 verification |
| **16** | E | **MinIO** | `ProbeMinIO` (`pkg/cloud/detector_storage.go`) | `Server: MinIO`, `/minio/health/ready` (reachability), `/minio/login` console | Health check establishes reachability; object storage data permissions require Phase 2.2 |

---

## 3. Safety and Access-Classification Verification

1. **Non-Enumerating Discovery Guarantee:**
   - Probes never send `?max-keys=1`, `?comp=list`, or `/documents` collection queries.
   - Probes never download object contents or database record payloads.
2. **Identity vs. Authorization Separation:**
   - Transport error, connection reachability, or protocol handshake response does not imply authorization or public data access.
   - Health check reachability (`/minio/health/ready` 200 OK) sets `PublicAccess: false`.
   - Redis `+PONG` and PostgreSQL SSL negotiation set `PublicAccess: false` and `AuthRequired: false`.
3. **Informational Finding Boundary:**
   - All Phase 2.1 discovery findings emit strictly at `SeverityInfo` with category `Service Discovery: <tech>`.
   - Out-of-scope targets produce `SeverityInfo` findings with category `Discovered Cloud Service (Out of Scope)` without active probe transmission.

---

## 4. Corrections Made During Final Closure

### CLI Classification Display Remediation (`cmd/felix/scan_cmd.go`)
- **Defect Identified:** Previously, discovered services defaulted to displaying `(Auth required)` whenever `PublicAccess` was false, erroneously implying authentication was required even when only a service reachability or protocol response had been observed.
- **Remediation:** Introduced `FormatServiceAccessState(ds cloud.DiscoveredService) string` enforcing 4 explicit, evidence-backed states:
  1. `Outside authorized scope`: Target outside authorized scope (`!ds.InScope`).
  2. `Access verified`: Unauthenticated public access empirically verified (`ds.PublicAccess`).
  3. `Authentication observed`: Active authentication challenge observed (`ds.AuthRequired`).
  4. `Access not verified`: Service identity confirmed, but data boundary/access policy is not verified (`!ds.PublicAccess && !ds.AuthRequired`).
- **Regression Testing:** Added `TestFormatServiceAccessState` to `cmd/felix/scan_cmd_test.go` covering all 4 classification states across Redis PONG, PostgreSQL SSL negotiation, MinIO health check, public storage, and out-of-scope services.

---

## 5. Verification Commands and Actual Outcomes

```powershell
# 1. Focused domain tests
go test -count=1 ./pkg/cloud/... ./pkg/discovery/... ./pkg/assessment/... ./cmd/...
# Result: ok felix/pkg/cloud (1.920s), felix/pkg/discovery (2.053s), felix/pkg/assessment (8.701s), felix/cmd/felix (2.943s)

# 2. Complete repository test suite
go test -count=1 ./cmd/... ./pkg/...
# Result: PASS (All 21 packages passed, 0 failures)

# 3. Static code analysis
go vet ./cmd/... ./pkg/...
# Result: Clean (0 warnings, 0 errors)

# 4. Binary compilation
go build -o bin/felix.exe ./cmd/felix
# Result: Clean build (bin/felix.exe generated)

# 5. Diff formatting check
git diff --check
# Result: Clean (0 whitespace/formatting errors)

# 6. Working tree status
git status --short
# Result: Tracked modifications in cmd/felix/scan_cmd.go, cmd/felix/scan_cmd_test.go, docs/engineering/

# 7. Benchmark baseline check
git status -- benchmarks/results/latest.json
# Result: Clean (benchmarks/results/latest.json remains pristine and untouched)
```

---

## 6. Git Publication & Repository State

- **Branch:** `main`
- **Initial Phase 2.1 Commit:** `33a53a1` (published to `origin/main`)
- **Published Files:** All 16 service detectors, safe client transport, CAM ingestion, and historical engineering audit documentation are published on `origin/main`.
- **Closure Commit:** Follow-up commit covering the CLI display correction, regression tests, and final acceptance report.
- **Repository Hygiene Note:** Historical audit documentation in `docs/engineering/` remains committed to preserve repository audit integrity without disruptive Git history rewriting.

---

## 7. Exit Gate Decision

### Evaluation Gate
> **“Supported services produce normalized, evidence-backed findings with correct classification and safe access verification.”**

### Final Status: `PASS WITH DOCUMENTED LIMITATIONS`

- **Verdict Justification:**
  - All 16 target services are fully implemented with non-enumerating probes, deterministic signatures, and CAM graph ingestion.
  - All Phase 1 safety, scope, and SSRF contracts are strictly enforced.
  - CLI display states honestly reflect access verification without false claims of authentication or exposure.
  - Documented limitations (e.g., Prisma internal ORM black-box detection constraints, deferral of unauthenticated collection/record exploit testing to Phase 2.2) are non-blocking architectural boundaries inherent to Phase 2.1 service discovery.

**Phase 2.1 is formally marked CLOSED.**
