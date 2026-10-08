# Felix Detection & Verification Model

This document explains the detection philosophy, evidence collection standards, empirical verification states, risk prioritization scoring, and multi-signal security stories implemented in Felix.

---

## Core Detection Philosophy

Felix is architected around a strict separation of concerns:

> **Discovery ≠ Detection ≠ Verification ≠ Vulnerability**

In modern web applications, client assets routinely contain API paths, public configuration values, third-party library tokens, and build artifacts. In traditional automated scanners, encountering these strings leads to widespread false positives. Felix establishes proof before assigning severity:

```text
Discovery
   │   Identifies an asset, route, endpoint, or configuration string.
   ▼
Detection
   │   Matches a pattern, heuristic, or security condition worthy of analysis.
   ▼
Verification
   │   Applies non-destructive empirical tests and analyzes response state.
   ▼
Evidence
   │   Records HTTP status, headers, location, and affirmative negative evidence.
   ▼
Risk Assessment
   │   Calculates deterministic 0–100 score weighted by verified exposure.
   ▼
Security Stories
   │   Correlates related signals into actionable incident narratives.
   ▼
Report
       Exports structured findings with remediation guidance.
```

---

## 1. Asset & Endpoint Intelligence

The asset ingestion engine in `pkg/crawler` and API detector in `pkg/api` discover client-accessible attack surfaces:
- **Discovered Asset Inventory:** HTML entrypoints, JavaScript bundles, stylesheets, web app manifests, and source maps (`//# sourceMappingURL=`).
- **Endpoint Route Extraction:** Static regex and AST-style parsing of client JavaScript for REST endpoints (`/api/...`, `/v1/...`) and GraphQL routes (`/graphql`, `/api/graphql`).
- **Endpoint Taxonomy Classification:** Categorizes routes into operational domains:
  - `auth`: Login, registration, token refresh, OAuth callbacks.
  - `user`: Profile, account settings, personal details.
  - `admin`: Backoffice consoles, management portals, metrics, internal dashboards.
  - `payments`: Checkout, billing, invoices, Stripe/PayPal webhooks.
  - `telemetry`: Analytics, event tracking, logging endpoints.
  - `debug`: Health checks, test routes, Swagger/OpenAPI docs.
  - `public`: Landing pages, marketing content, static assets.
  - `unknown`: Non-classified URI paths.

---

## 2. Secret Intelligence

Implemented in `pkg/secrets`, this subsystem discovers potential credentials in client assets:

### Supported Secret Patterns
- **Cloud Infrastructure:** AWS Access Key IDs (`AKIA...`), Google Cloud Platform API keys (`AIza...`).
- **BaaS Providers:** Supabase anonymous keys, Supabase service_role keys, Firebase Database secrets.
- **Payment Gateways:** Stripe publishable keys (`pk_live_...`), Stripe secret keys (`sk_live_...`).
- **Developer & SaaS Services:** GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`), Slack Incoming Webhooks (`hooks.slack.com/services/...`), SendGrid API keys (`SG....`), Mailgun API keys (`key-...`), Twilio Account SIDs and Auth Tokens, OpenAI API keys (`sk-...`).
- **Cryptography & Tokens:** RSA/EC Private Key blocks (`BEGIN PRIVATE KEY`), JSON Web Tokens (JWT) inspection.

### Shannon Entropy Heuristics
For strings without standardized prefixes, Felix evaluates Shannon entropy:
$$H = -\sum_{i=1}^{n} p_i \log_2(p_i)$$
- Strings between 16 and 128 characters with entropy exceeding 4.5–5.0 bits/char are flagged as high-entropy candidates.
- **Alphabet Filtering:** Differentiates Hexadecimal, Base64, and Alphanumeric character sets to eliminate structured false positives.

### False-Positive Suppression
Felix suppresses common development artifacts that mimic high entropy:
- UUIDs and GUIDs
- Git 40-character commit hashes
- Webpack and Next.js chunk hashes (e.g. `0lcc2ylewy3e9.js`)
- CSS hex color strings (`#ffffff`, `#3b82f6`)
- Development test placeholders (`YOUR_API_KEY_HERE`, `sk_test_...`)
- Common JavaScript vendor libraries (React, Vue, Angular, Lodash)

### Redaction & Verification
- **Static Verification State:** Detected client secrets remain in the `NOT_VERIFIED` verification state. Client-side static analysis does not test credentials against third-party provider APIs (adhering to Felix's non-destructive, zero-transmission policy).
- **Mandatory Redaction:** Values are masked in memory and across all outputs (e.g. `sb_p****************ud_e`).

---

## 3. Cloud & BaaS Intelligence

Implemented in `pkg/cloud`, this subsystem audits cloud backends referenced in client assets:

### Supported Providers
- **Supabase:** Evaluates backend URLs (`*.supabase.co`).
  - *Key Separation:* Distinguishes `anon` (public client key) from `service_role` (administrative bypass key).
  - *Safe Verification:* Issues a bounded read-only GET request to public REST endpoints.
  - *RLS Assessment:* Confirms whether Row Level Security (RLS) is active.
- **Firebase Realtime Database:** Evaluates database endpoints (`*.firebaseio.com`).
  - *Safe Verification:* Checks the public `/.json` endpoint for unauthenticated read permissions.
- **AWS S3 & Google Cloud Storage:** Evaluates storage buckets (`*.s3.amazonaws.com`, `storage.googleapis.com/*`).
  - *Safe Verification:* Issues read-only GET/HEAD requests to evaluate public listing and object accessibility.

### Negative Evidence Handling
If a cloud endpoint returns `401 Unauthorized` or `403 Forbidden`, Felix records affirmative negative evidence proving that backend authentication boundaries are actively enforced. The finding is marked `NOT_EXPOSED` with `LOW` or `INFO` severity.

---

## 4. API & Application Security Analysis

Implemented in `pkg/api`, this subsystem audits application security configurations:

### Authentication-State Reasoning
Felix probes discovered endpoints using safe GET/HEAD requests and interprets HTTP responses:
- `401 Unauthorized / 403 Forbidden`: Authenticated boundary confirmed; access denied to unauthenticated clients (`NOT_EXPOSED`).
- `200 OK`: Publicly accessible resource. Evaluated against route taxonomy (e.g. `admin` vs `public`).
- `301 / 302 / 308`: Redirect response. Proves unauthenticated clients are redirected (e.g. to login or canonical URLs).
- `404 Not Found`: Non-existent route.

### CORS Origin Reflection
Felix tests cross-origin resource sharing by providing an arbitrary test origin (`https://felix.invalid`):
- **Wildcard Origin (`Access-Control-Allow-Origin: *`):** Evaluated as informational (`OBSERVED`). Acceptable for public content; unsafe for tenant data.
- **Credentialed Origin Reflection (`Access-Control-Allow-Credentials: true`):** If the untrusted origin is echoed back alongside credential allowance, this is flagged as a `HIGH` severity `VERIFIED` CORS vulnerability.
- **Negative Evidence:** If the server does not reflect the test origin or omits CORS headers, the test origin was rejected.

### GraphQL Introspection
Felix submits a safe query (`{"query":"query { __schema { types { name } } }"}`) to discover if schema introspection is exposed:
- `VERIFIED`: If the response contains `__schema` types, full API schema introspection is active in production (`MEDIUM` severity).
- `NOT_EXPOSED`: If the endpoint returns `400 Bad Request`, `405 Method Not Allowed`, or GraphQL validation errors prohibiting introspection.

### Defensive Security Headers
Felix evaluates response headers against defense-in-depth best practices:
- **Content-Security-Policy (CSP):** Verified absent or misconfigured (`LOW` severity).
- **Strict-Transport-Security (HSTS):** Verified absent on HTTPS endpoints (`LOW` severity).
- **X-Frame-Options / frame-ancestors:** Verified absent clickjacking defense (`LOW` severity).
- **X-Content-Type-Options:** Verified `nosniff` directive (`INFO` severity).
- **Permissions-Policy:** Verified browser capability gating (`INFO` severity).
- **Referrer-Policy:** Verified referrer leakage controls (`INFO` severity).

---

## 5. Verification States Matrix

Felix classifies every finding using an empirical verification state reflecting evidentiary strength:

| Verification State | Meaning | Typical Evidence | Risk Implication |
| :--- | :--- | :--- | :--- |
| **`VERIFIED`** | Established with affirmative empirical proof. | Accessible database rows, active GraphQL `__schema`, credentialed CORS reflection, missing required security header. | Maximum score weight within severity tier. |
| **`DETECTED`** | Security-relevant pattern identified with contextual support. | API route identified in code, provider infrastructure reference. | Moderate score weight. |
| **`OBSERVED`** | Discovered asset or inventory item confirmed active. | Public endpoint responding 200 OK, uncredentialed wildcard CORS header, ingested asset. | Informational baseline weight. |
| **`NOT_VERIFIED`** | Candidate identified statically but not verified over the network. | High-entropy secret candidate, unverified third-party token. | Low score weight; requires human engineering review. |
| **`NOT_EXPOSED`** | Verification produced affirmative evidence that the resource is defended. | HTTP `401 Unauthorized` or `403 Forbidden` response, rejected CORS origin, disabled introspection. | Zero risk contribution; negative score adjustment. |

---

## 6. Structured Evidence Details Model

Every finding contains an `EvidenceDetails` record (`pkg/report/model.go`):

```json
{
  "observation": "Response headers do not include Content-Security-Policy.",
  "location": "https://example.com",
  "http_method": "GET",
  "http_status": 200,
  "content_type": "text/html; charset=UTF-8",
  "detection_method": "http_header_inspection",
  "detection_status": "header_missing",
  "negative_evidence": "Informational hardening observation; does not constitute an exploitable vulnerability by itself."
}
```

- **Observation:** Clear technical summary of what Felix observed.
- **Location:** URI, endpoint, or file origin with line number.
- **HTTP Method & Status:** Concrete HTTP interaction details.
- **Detection Method:** Explains how the condition was detected (static pattern, entropy heuristic, HTTP probe, header inspection).
- **Negative Evidence:** Explicit explanation of safety barriers, defensive headers, or non-exploitable contexts observed.

---

## 7. Deterministic Risk Scoring Model

The **Felix Risk Score (0–100)** is an explainable exposure metric designed for operational prioritization. It is **not CVSS**:

### Scoring Principles
1. **Verification Multipliers:** Findings verified with affirmative evidence (`VERIFIED`) contribute full base points; unverified candidates (`NOT_VERIFIED`) receive reduced weighting.
2. **Negative Evidence Adjustments:** Confirmed defense boundaries (`NOT_EXPOSED`) reduce exposure scores.
3. **Defense-in-Depth Caps:** Security header findings (missing CSP, HSTS, XFO) are capped at a maximum combined score contribution of **20 points**.
4. **Diminishing Marginal Returns:** Multiple repetitive findings within the same category taper off logarithmically to prevent score inflation.

### Risk Levels
- **`0` (CLEAN):** Zero actionable findings.
- **`1–20` (LOW):** Defense-in-depth hardening opportunities (e.g. missing response headers) and asset inventory observations.
- **`21–59` (MEDIUM):** Informational disclosures, enabled GraphQL introspection, or sensitive route exposures.
- **`60–89` (HIGH):** Credentialed CORS reflection, unauthenticated sensitive API endpoints, or exposed cloud backends.
- **`90–100` (CRITICAL):** Confirmed administrative cloud bypass (e.g. leaked `service_role` key + RLS disabled) or exposed production credentials.

---

## 8. Correlated Security Stories

Felix groups discrete findings into unified **Security Stories** in `pkg/report/correlate.go`:

| Security Story | Correlated Conditions | Impact |
| :--- | :--- | :--- |
| **Exposed Cloud Administrative Capability** | Supabase/Firebase provider endpoint + leaked service key + accessible REST API | Complete unauthorized database compromise and administrative bypass. |
| **Unauthenticated Sensitive Route Exposure** | Discovered sensitive API endpoint + HTTP 200 OK unauthenticated response | Direct data exposure and bypass of application authentication gates. |
| **Credentialed Cross-Origin Exposure** | API endpoint + CORS test origin reflected + `Access-Control-Allow-Credentials: true` | Cross-origin theft of authenticated session data and private tenant records. |
| **Production Schema & Endpoint Disclosure** | Discovered GraphQL endpoint + active `__schema` introspection | Complete exposure of internal data models, mutations, and hidden routes. |
| **High-Entropy Secret in Client Bundle** | High-entropy candidate string + key assignment context in public JavaScript | Exposure of backend service tokens to client-side reverse engineering. |

---

## Navigation & Cross-References

- **[README](README.md)** — Project overview.
- **[Architecture Guide](ARCHITECTURE.md)** — Subsystem design and concurrency pipeline.
- **[Operator Usage Guide](USAGE.md)** — CLI commands, options, and exit codes.
- **[Security & Safety Controls](SECURITY.md)** — Safety boundaries and non-destructive guarantees.
- **[Limitations & Non-Goals](LIMITATIONS.md)** — Boundaries of black-box scanning.
- **[Contributing Guide](CONTRIBUTING.md)** — How to add new detection logic and regression tests.
