# FELIX Commercial Service Specification

## Service 01: Authorised External Web Application & API Security Assessment

> **Service ID:** `SVC-EXT-WEB-API-01`  
> **Delivery Model:** Remote, Evidence-First Assessment  
> **Platform Engine:** FELIX Proprietary Offensive Security Engine (Private)  
> **Target Audience:** Indian & International B2B SaaS Startups, Software Consultancies, and Tech-Enabled SMEs  
> **Service Version:** 1.0 (Commercial Launch Edition)  

---

## 1. Executive Summary & Objective

The **Authorised External Web Application & API Security Assessment** is a specialized, non-destructive technical evaluation of an organization's public-facing attack surface. 

Rather than delivering raw scanner output or speculative vulnerability lists, this service combines the deterministic verification power of FELIX with human technical review to identify:
- Verifiable web application vulnerabilities.
- REST/GraphQL API authorization, authentication, and data exposure flaws.
- Public cloud storage and asset leakage risks.
- Actionable, code-level remediation steps.

**Core Value Proposition:**
- **Zero Hallucinations / Zero Speculative Alerts:** Every actionable finding is backed by empirical HTTP request/response evidence or mathematically verified out-of-band callbacks.
- **Non-Destructive Guarantee:** Strict rate-limiting, benign proof-of-concept testing, and zero brute-force/denial-of-service fuzzing preserve production uptime and data integrity.
- **Actionable Engineering Guidance:** Developers receive reproduction curl commands, exact parameter locations, and code diff recommendations.

---

## 2. Standard Service Scope

### 2.1 In-Scope Targets & Capabilities

| Target Domain | Technical Capabilities & Assessment Vectors |
| :--- | :--- |
| **Public Web Applications** | Single Page Applications (React, Vue, Angular), server-rendered web portals, authentication gateways, session state management, cross-site scripting (XSS), server-side request forgery (SSRF), open redirects, and security header configurations. |
| **REST & GraphQL APIs** | Parameter parsing, Broken Object Level Authorization (BOLA / IDOR), Broken Function Level Authorization (BFLA), unauthenticated endpoint exposure, mass assignment, verbose error stack traces, and CORS misconfigurations. |
| **Client-Side Asset Intelligence** | Automated parsing of public JavaScript bundles, source-map analysis, exposed staging API endpoints, route discovery, and high-entropy secret detection (hardcoded credentials, leaked tokens). |
| **Public Cloud & Asset Exposure** | Discovery of public cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob Storage) directly associated with the target domain. |

### 2.2 Explicit Exclusions (Strict Scope Guardrails)

The following activities are strictly prohibited from this service:
1. **Denial of Service (DoS/DDoS):** No stress testing, connection starvation, or bandwidth flooding.
2. **Social Engineering & Phishing:** No targeting of customer employees, contractors, or support channels.
3. **Physical Penetration Testing:** No attempts to access physical offices, datacenters, or customer premises.
4. **Third-Party Infrastructure:** Shared cloud multi-tenant infrastructure, SaaS providers (e.g., Salesforce, Google Workspace), payment gateways (Stripe, Razorpay) are tested only at the customer’s integration boundary, never against the provider's core systems.
5. **Data Destruction or Modification:** Payloads are non-destructive and read-only. No modification, deletion, or exfiltration of sensitive customer production records.

---

## 3. Engagement Lifecycle & Workflow

```text
  [Stage 1: Discovery]
         │ (Requirements, target URLs, tech stack review)
         ▼
  [Stage 2: Authorization]
         │ (Written RoE, ownership verification, mutual NDA)
         ▼
  [Stage 3: Assessment Execution]
         │ (Reconnaissance -> Deterministic Crawl -> Non-Destructive Probing)
         ▼
  [Stage 4: Human Review & Verification]
         │ (False-positive elimination, business context ranking)
         ▼
  [Stage 5: Report Delivery & Handover]
         │ (Executive Summary + Technical Findings + Code Diffs)
         ▼
  [Stage 6: Remediation & Retesting]
         │ (Verification of applied patches within 30 days)
         ▼
  [Stage 7: Engagement Closure]
         └ (Cryptographic Letter of Attestation + Secure Data Purge)
```

### Detailed Workflow Stages

- **Stage 1 — Discovery & Scoping:** Review domain names, API base URLs, staging vs. production targets, and peak traffic hours.
- **Stage 2 — Written Authorization & Governance:** Execution of the Rules of Engagement (RoE) and domain ownership validation (DNS TXT record or verified security contact).
- **Stage 3 — Assessment Execution:** FELIX executes deterministic passive recon, headless JavaScript link analysis, and rate-limited verification probes.
- **Stage 4 — Human Technical Validation:** The technical lead manually reviews every observation, eliminates non-actionable signals, and prioritizes findings by business impact.
- **Stage 5 — Reporting & Debrief:** Delivery of the formal assessment report and a 30-minute technical walkthrough with the customer's engineering team.
- **Stage 6 — Remediation Retest:** Within 30 days of report delivery, the customer requests verification of applied fixes. Retesting confirms resolution without re-billing full assessment fees.
- **Stage 7 — Attestation & Data Purge:** Issuance of the final Letter of Attestation and cryptographic wiping of transient assessment traces.

---

## 4. Deliverables Package

Every completed engagement delivers three distinct, human-reviewed artifacts:

1. **Executive Security Summary (PDF):**
   - High-level risk score and posture rating.
   - Strategic breakdown of vulnerabilities for executive leadership and board members.
   - Regulatory exposure overview (contextualized against Indian DPDP Act 2023 / EU GDPR where applicable).
2. **Comprehensive Technical Findings Report (PDF/HTML):**
   - Vulnerability title, severity (CVSS 3.1 & Risk Matrix), and OWASP Top 10 categorization.
   - Deterministic proof-of-concept: Exact HTTP request, response headers, and reproduction `curl` command.
   - Remediation blueprint: Specific code-level guidance, architecture adjustments, and configuration fixes.
3. **Formal Letter of Attestation:**
   - Cryptographically verifiable summary of the assessment window, scope, and post-remediation status.
   - Suitable for sharing with enterprise prospective clients, investors, or compliance auditors.

---

## 5. Commercial Tiers & Pilot Pricing

| Commercial Tier | Scope Boundary | Target Turnaround | India Pilot (INR) | International Pilot (USD) |
| :--- | :--- | :---: | :---: | :---: |
| **Validation Pilot Tier** | 1 Core Web App + Up to 10 Key API Endpoints | 2–3 Days | **₹15,000 – ₹25,000** | **$350 – $500** |
| **Standard SaaS Assessment** | 1 Full Web App + Up to 35 Endpoints + Public Cloud Storage | 3–5 Days | **₹45,000 – ₹75,000** | **$900 – $1,500** |
| **Enterprise Attack Surface** | Multi-Domain Perimeter + Comprehensive API Suite + Mobile Correlation | 5–7 Days | Custom Quote | Custom Quote |

*Note on Retest Inclusion:* All packages include **one complimentary retest** of verified vulnerabilities completed within 30 days of initial report handoff.
