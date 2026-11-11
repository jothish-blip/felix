# Rules of Engagement & Written Testing Authorisation

> **Document Type:** Legally Binding Permission & Rules of Engagement (RoE)  
> **Engagement Ref:** `ROE-FELIX-[YEAR]-[CLIENT-ID]`  
> **Jurisdiction:** Indian Information Technology Act, 2000 (Sections 43 & 66 Safe Harbor) & Applicable Local Law  

---

## 1. Parties & Purpose

This Rules of Engagement Agreement ("Agreement") is entered into between:

1. **Assessor:** Jothish, operating FELIX Security Services ("Assessor"), and
2. **Customer:** [Client Legal Entity Name] ("Customer"), having its principal office at [Address].

**Purpose:** Customer expressly authorizes Assessor to perform an external web application and API security assessment on designated assets to evaluate security vulnerabilities, verify authorization controls, and provide remediation recommendations.

---

## 2. Customer Authority & Ownership Warranty

Customer warrants and represents that:
1. Customer is the lawful owner, licensee, or authorized operator of all domains, systems, APIs, and IP addresses designated in **Section 3 (Agreed Target Scope)**.
2. Customer possesses full legal authority to grant permission to perform security testing against these assets.
3. Conducting this assessment does not violate Customer's terms of service with hosting, cloud, or telecommunications providers.

---

## 3. Agreed Target Scope

Testing shall be strictly confined to the targets itemized below. Any system, subdomain, or IP address not explicitly listed herein is strictly **OUT OF SCOPE**.

### 3.1 In-Scope Targets

| Target URL / Fully Qualified Domain Name (FQDN) | Target Environment | Permitted Test Types |
| :--- | :---: | :--- |
| `https://app.[client-domain].com` | Production / Staging | Web vulnerability scanning, session testing |
| `https://api.[client-domain].com` | Production / Staging | API authorization checks, parameter testing |
| `[Specific Subdomain or Cloud Bucket]` | Production / Staging | Storage exposure check, CORS configuration |

### 3.2 Explicit Exclusions (Forbidden Techniques)
The Assessor shall NOT:
- Perform Denial of Service (DoS, DDoS) or connection-starvation attacks.
- Attempt unauthorized modification, deletion, or exfiltration of production database records.
- Conduct physical security attacks or social engineering/phishing of Customer personnel.
- Probe or target any third-party infrastructure (e.g., payment gateways, external SaaS integrations).

---

## 4. Execution Parameters & Guardrails

1. **Testing Window:**
   - Start Date & Time: `[YYYY-MM-DD 09:00 IST / UTC]`
   - End Date & Time: `[YYYY-MM-DD 18:00 IST / UTC]`
   - Daily Allowed Windows: `[e.g., Monday to Friday, 10:00 to 19:00 IST]`
2. **Assessor Source IP Addresses:**
   - Primary Assessor IP: `[Assessor Public IP Address]`
   - Testing Identifier Header: All HTTP/HTTPS requests originating from the FELIX engine shall carry the custom header:
     ```http
     X-Security-Assessment: FELIX-Authorized-[CLIENT-ID]
     ```
3. **Emergency Disruption Protocol:**
   - In the unlikely event that Customer systems exhibit abnormal latency, instability, or performance degradation, testing shall cease immediately upon notice.
   - **Customer Emergency Contact:** [Name], [Phone], [Email]
   - **Assessor Emergency Contact:** Jothish, [Phone], [Email]

---

## 5. Confidentiality & Data Protection

1. **Non-Disclosure:** All findings, vulnerability details, system configurations, and Customer data discovered during the assessment are strictly confidential. Assessor shall not disclose findings to any third party without Customer's prior written consent.
2. **Evidence Retention & Purge:**
   - Raw HTTP request/response logs and evidence receipts collected during testing shall be stored in encrypted volumes (AES-256).
   - Within **14 days** of the conclusion of the retest cycle, all transient customer testing data, session tokens, and local cache entries shall be securely wiped from Assessor's systems.
   - The final signed report and attestation shall be retained for record-keeping as agreed.
3. **Data Protection Compliance:** Testing shall adhere to applicable data privacy requirements under the Digital Personal Data Protection Act, 2023 (India) and EU GDPR (where applicable). Assessor shall not retain personal data discovered during testing beyond what is strictly necessary for vulnerability proof.

---

## 6. Limitation of Liability & Hold Harmless

1. **Non-Destructive Standard of Care:** Assessor agrees to exercise professional diligence and employ non-destructive testing methodologies.
2. **Hold Harmless:** To the extent permitted by law, Customer holds Assessor harmless from any unintended disruptions or performance impacts arising from authorized testing performed within the agreed scope.
3. **Liability Cap:** In no event shall either party's aggregate liability under this Agreement exceed the total fees paid by Customer for this engagement.

---

## 7. Signatures & Acceptance

By signing below, the parties confirm that they have read, understood, and agreed to these Rules of Engagement.

**For Customer ([Client Company Name]):**

Authorized Signature: _____________________________________________  
Printed Name: ____________________________________________________  
Title: ___________________________________________________________  
Date: ____________________________________________________________  

**For Assessor (FELIX Security Services):**

Authorized Signature: _____________________________________________  
Printed Name: **Jothish**  
Title: **Founder & Principal Security Engineer**  
Date: ____________________________________________________________  
