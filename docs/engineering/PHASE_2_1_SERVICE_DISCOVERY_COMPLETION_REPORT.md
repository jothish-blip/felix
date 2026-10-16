# FELIX — Phase 2.1: Universal Cloud, Database, and Storage Service Discovery
## Engineering Completion & Verification Report

**Date:** 2026-10-16  
**Status:** COMPLETE & REMEDIATED  
**Phase:** Phase 2.1 — Service Discovery  
**Target Repository:** `jothish-blip/felix` (Branch `main`)  
**Platform / Toolchain:** Windows amd64, Go 1.27.0  

---

## 1. Executive Summary

Phase 2.1 implements universal, passive and active non-destructive service discovery across all **16 mandatory service targets** defined in the FELIX master roadmap. Every discovered service is identified empirically through deterministic signatures, wire protocol handshakes, and bounded HTTP responses. Discovered services are ingested directly into FELIX's Common Asset Model (CAM) graph, establishing typed Database, Storage, and Service entities linked by verified relational edges.

Following a thorough safety audit, all discovery probes have been remediated to adhere strictly to non-enumerating, safe protocols:
- **Cloud Storage Non-Enumeration:** Ordinary discovery eliminates bucket/container object listing queries (`?max-keys=1`, `?comp=list`). Probes use non-enumerating `HEAD` and service header inspection (`Server: AmazonS3`, `x-amz-request-id`, `Server: Windows-Azure-Blob`, `Server: UploadServer`/`GSE`, `Server: MinIO`).
- **Firebase / Firestore Non-Enumeration:** Removed database record retrieval, collection enumeration, and shallow key searches (`/.json?shallow=true`, `/documents`). RTDB uses non-enumerating `HEAD /.json`; Firestore queries database root metadata (`/databases/(default)`).
- **Identity vs Access Classifications:**
  - Redis `+PONG` confirms protocol identity, not public data readability (`PublicAccess: false`, `AuthRequired: false`).
  - PostgreSQL SSL negotiation (`'S'`/`'N'`) confirms protocol presence, not credentials or auth policy (`AuthRequired: false`, `PublicAccess: false`).
  - MySQL Initial Handshake Packet confirms server protocol, not auth policy (`AuthRequired: false`, `PublicAccess: false`).
  - MinIO health check (200 OK) confirms reachability, not storage exposure (`PublicAccess: false`).
- **Finding Severities:** All service discovery findings are strictly informational (`SeverityInfo`). Proving unauthenticated data boundaries or public exposure is strictly deferred to Phase 2.2.
- **SSRF & Scope Protection:** Probes strictly respect scope authorization (`isAllowed`, `isExcluded`) and utilize `crawler.NewSafeDialContext` to prohibit loopback, RFC 1918 private subnets, and cloud metadata (`169.254.169.254`, `fd00:ec2::254`).

---

## 2. 16-Service Coverage & Implementation Matrix

| Target # | Group | Service / Technology | Detection Method | Signatures & Verification Protocol | Auth & Access Handling | Scope / Status Outcome |
|---|---|---|---|---|---|---|
| **1** | A | **Elasticsearch** | HTTP Probe / Passive Regex | `GET /` -> JSON tagline `"You Know, for Search"`, cluster/node name, version; header `X-elastic-product: Elasticsearch` | 401 with `Basic realm="security"` -> `AuthRequired: true`; 200 OK -> `AuthRequired: false`, `PublicAccess: false` (indices read deferred to Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **2** | A | **MongoDB** | TCP Probe / HTTP Driver Probe | Safe TCP BSON `isMaster` (OP_QUERY 2004) wire handshake (`"ismaster"`, `"isWritablePrimary"`); HTTP port notice (`"trying to access MongoDB over HTTP on the native driver port"`) | Wire protocol auth error -> `AuthRequired: true`; BSON handshake response -> `PublicAccess: false` (collection access deferred to Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **3** | A | **Redis** | TCP Probe / Passive Regex | Safe TCP send `PING\r\n`; read RESP response (`+PONG\r\n`, `-NOAUTH`, `-DENIED protected mode`) | `-NOAUTH` / `-DENIED` -> `AuthRequired: true`; `+PONG` -> `AuthRequired: false`, `PublicAccess: false` (keyspace access deferred to Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **4** | A | **PostgreSQL** | TCP Probe / Passive Regex | Safe TCP send PostgreSQL `SSLRequest` (8 bytes: `\x00\x00\x00\x08\x04\xd2\x16\x2f`); server responds with single byte `'S'` (SSL supported) or `'N'` | Protocol confirms PostgreSQL; `AuthRequired: false`, `PublicAccess: false` (server auth policy evaluated in Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **5** | A | **MySQL** | TCP Probe / Passive Regex | Safe TCP read Initial Handshake Packet (server-speaks-first): Protocol 10 (`0x0A`) + null-terminated server version string; or Error Packet (byte `0xFF` + code 1129/1130) | Initial Handshake confirms protocol; `AuthRequired: false`, `PublicAccess: false` (login policy evaluated in Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **6** | B | **Mongo Express** | HTTP Probe / Passive Regex | HTTP `GET /`: HTML `<title>Mongo Express</title>`, links `/db/`, cookies `mongo-express` | HTTP 401 with `Basic realm="mongo-express"` -> `AuthRequired: true`; 200 OK -> `AuthRequired: false`, `PublicAccess: false` (CRUD authorization deferred) | `DETECTED`, `SeverityInfo` |
| **7** | C | **Supabase** | HTTP Probe / Passive Regex / JWT | Hostname `*.supabase.co`, `/rest/v1/` endpoint, Kong header `sb-gateway-mode`, JWT claims (`iss: "supabase"`, `role: "anon"`/`"service_role"`) | HTTP 401 `{"message":"Invalid API key"}` -> `AuthRequired: true`; 200 OK -> `PublicAccess: false` (RLS policies deferred to Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **8** | C | **PostgREST** | HTTP Probe / Passive Regex | Response header `Range-Unit: items`; OpenAPI spec title `"PostgREST API"`; error codes matching `PGRST\d{3}` | OpenAPI discovery / PGRST code -> `PublicAccess: false` | `DETECTED`, `SeverityInfo` |
| **9** | C | **Hasura** | HTTP Probe / Passive Regex | HTTP `/v1/version` -> version JSON; `/v1/graphql` empty POST -> validation error; header `x-hasura-role` | `x-hasura-role != "anonymous"` -> `AuthRequired: true`; `PublicAccess: false` | `DETECTED`, `SeverityInfo` |
| **10** | C | **Prisma** | Passive Bundle / Error Signature Analysis | JS bundles containing `@prisma/client`, `.prisma/client`, `schema.prisma`; response error codes `P2002`, `P2025`. Negative case reports explicit limitation note (internal ORM) | Embedded server-side ORM; black-box detection requires bundle traces or leaked error codes | `DETECTED` or `NOT_DETECTED` with limitation |
| **11** | D | **Firebase Realtime DB** | HTTP Probe / Passive Regex | Hostname `*.firebaseio.com`, `*.firebasedatabase.app`; non-enumerating `HEAD /.json` -> 200 OK or 401 | 401 `"Permission denied"` -> `AuthRequired: true`; 200 OK -> `AuthRequired: false`, `PublicAccess: false` (data boundary deferred) | `DETECTED`, `SeverityInfo` |
| **12** | D | **Cloud Firestore** | HTTP Probe / Passive Regex | Non-enumerating metadata query: `firestore.googleapis.com/v1/projects/{id}/databases/(default)` | 403 `PERMISSION_DENIED` -> `AuthRequired: true`; 200 OK -> `PublicAccess: false` (collection rules deferred to Phase 2.2) | `DETECTED`, `SeverityInfo` |
| **13** | E | **AWS S3** | HTTP Probe / Passive Regex | Hostname `*.s3.amazonaws.com`; non-enumerating `HEAD /`; headers `Server: AmazonS3`, `x-amz-request-id` | 403 `AccessDenied` -> `AuthRequired: true`; 200 OK -> `PublicAccess: false` (read/write permissions deferred) | `DETECTED`, `SeverityInfo` |
| **14** | E | **Azure Blob Storage** | HTTP Probe / Passive Regex | Hostname `*.blob.core.windows.net`; non-enumerating `HEAD /`; headers `Server: Windows-Azure-Blob/1.0`, `x-ms-request-id` | 403 `AuthenticationFailed` -> `AuthRequired: true`; 200 OK -> `PublicAccess: false` (blob permissions deferred) | `DETECTED`, `SeverityInfo` |
| **15** | E | **Google Cloud Storage** | HTTP Probe / Passive Regex | Hostname `storage.googleapis.com/*`; non-enumerating `HEAD /`; headers `Server: UploadServer` / `Server: GSE`, `x-goog-generation` | 403 `AccessDenied` -> `AuthRequired: true`; 200 OK -> `PublicAccess: false` (object permissions deferred) | `DETECTED`, `SeverityInfo` |
| **16** | E | **MinIO** | HTTP Probe / Passive Regex | Header `Server: MinIO`, `x-minio-deployment-id`; endpoints `/minio/health/ready` (200 OK), `/minio/login` (`<title>MinIO Console</title>`) | Console login -> `AuthRequired: true`; `/minio/health/ready` 200 OK -> `PublicAccess: false` (reachability only) | `DETECTED`, `SeverityInfo` |

---

## 3. Architecture & Code Changes

### A. Core Models (`pkg/cloud/service_types.go`)
- Strongly typed enums: `ServiceFamily`, `ServiceTechnology`, and `DiscoveryOutcome` (`DETECTED`, `POSSIBLE`, `NOT_DETECTED`, `INCONCLUSIVE`, `ERROR`).
- `DiscoveredService` captures technology, family, empirical outcome, confidence, endpoint, host, port, protocol, detection method, version, auth requirement, public access status, metadata, limitations, and timestamps.
- Deterministic `CanonicalID()` and SHA-256 `Fingerprint()` for stable deduplication.
- `ToFinding()` strictly enforces `SeverityInfo` across all discovery findings, and formats out-of-scope discoveries with category `Discovered Cloud Service (Out of Scope)`.

### B. Safe TCP & HTTP Probing (`pkg/cloud/client.go`)
- `cloud.Client` integrates `SafeDialContext(ctx, network, addr)` leveraging `crawler.NewSafeDialContext`.
- Prohibits cloud metadata (`169.254.169.254`, `fd00:ec2::254`), loopback addresses, and private subnets unless explicitly permitted.
- Enforces scope authorization (`isAllowed` and `isExcluded`) prior to outbound network calls.

### C. Dedicated Service Detectors
- `pkg/cloud/detector_databases.go`: Direct database & search engines (Elasticsearch, MongoDB, Redis, PostgreSQL, MySQL).
- `pkg/cloud/detector_admin.go`: Database admin interfaces (Mongo Express).
- `pkg/cloud/detector_backend.go`: Backend & database interfaces (Supabase, PostgREST, Hasura, Prisma).
- `pkg/cloud/detector_firebase.go`: Firebase databases (Firebase Realtime Database, Cloud Firestore).
- `pkg/cloud/detector_storage.go`: Cloud & object storage (AWS S3, Azure Blob, GCS, MinIO).
- `pkg/cloud/service_discovery.go`: Shared coordinator `ServiceDiscoveryEngine` managing bounded concurrent worker pools and candidate verification.

### D. Common Asset Model Integration (`pkg/discovery/asset_factory.go`)
- `IngestDiscoveredServices(inv, asmID, execID, targetID, rootAppID, services)`.
- Mapped discovered services to strongly typed CAM entities:
  - `FamilyDirectDatabase` & `FamilyFirebase` -> `AssetTypeDatabase` (`DatabaseDetails`)
  - `FamilyObjectStorage` -> `AssetTypeStorage` (`StorageDetails`)
  - `FamilyDatabaseAdmin` & `FamilyBackendInterface` -> `AssetTypeService` (`ServiceDetails`) and `AssetTypeHost` (`HostDetails`)
- Generated relational graph edges:
  - `Application -> RelUsesDatabase -> Database`
  - `Application -> RelUsesStorage -> Storage`
  - `Application -> RelExposesService -> Service`
  - `Host -> RelHostsService -> Service`

### E. Pipeline & CLI Integration
- `pkg/assessment/controller.go`: Updated assessment pipeline to invoke `discovery.IngestDiscoveredServices` when `cloudRes.DiscoveredServices` are returned.
- `cmd/felix/scan_cmd.go`: Enhanced CLI terminal output to present discovered services, technologies, endpoints, and authentication states.

---

## 4. Verification & Quality Gates

### A. Test Execution
```powershell
go test -count=1 ./cmd/... ./pkg/...
```
**Outcome:** PASSED (100% across all 21 packages, 0 failures, 0 skipped).
```
ok  	felix/cmd/felix	7.374s
ok  	felix/pkg/api	1.599s
ok  	felix/pkg/apisec	2.732s
ok  	felix/pkg/assessment	16.180s
ok  	felix/pkg/auth	1.203s
ok  	felix/pkg/authz	1.320s
ok  	felix/pkg/businesslogic	1.930s
ok  	felix/pkg/cloud	0.989s
ok  	felix/pkg/cloudsec	3.794s
ok  	felix/pkg/config	1.109s
ok  	felix/pkg/correlation	1.013s
ok  	felix/pkg/crawler	12.120s
ok  	felix/pkg/discovery	3.863s
ok  	felix/pkg/operator	5.678s
ok  	felix/pkg/report	3.478s
ok  	felix/pkg/secrets	3.561s
ok  	felix/pkg/sessionsec	1.245s
ok  	felix/pkg/ui	0.535s
ok  	felix/pkg/update	2.298s
ok  	felix/pkg/verification	1.362s
ok  	felix/pkg/webvuln	3.120s
```

### B. Static Code Analysis
```powershell
go vet ./cmd/... ./pkg/...
```
**Outcome:** Clean (0 errors, 0 warnings).

### C. Binary Compilation
```powershell
go build -o bin/felix.exe ./cmd/felix
```
**Outcome:** Binary compiled successfully; executes cleanly on `windows/amd64` under Go 1.27.0.

### D. Formatting & Diff Check
```powershell
git diff --check
```
**Outcome:** Clean (0 whitespace errors).

### E. Baseline Invariant
`benchmarks/results/latest.json` remains pristine and untouched.

---

## 5. Exit Gate Decision

Phase 2.1 — Universal Cloud, Database and Storage Service Discovery meets all roadmap acceptance criteria and safety audit standards. All 16 target services are fully implemented, verified with automated unit and regression tests, and integrated into the Common Asset Model without any unauthorized exploit primitives.
