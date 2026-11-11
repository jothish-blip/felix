# FELIX Commercial Outreach Playbook

> **Target:** Early-Stage SaaS Founders, CTOs, VP Engineering, and Software Agency Leaders  
> **Positioning:** High-Trust, Evidence-First Security Assessment (Zero Sales Fluff, Zero Destructive Exploits)  
> **Author:** Jothish | Founder & Lead Assessor  

---

## 1. Core Messaging Principles

When engaging technical founders and CTOs:
1. **Never use fear, uncertainty, or doubt (FUD):** Avoid alarmist language like *"Your website is about to get hacked"*.
2. **Be specific and technical:** Speak engineer-to-engineer. Emphasize *verifiable proof* (curl reproductions) over generic scorecards.
3. **Respect their time:** Keep cold messages under 120 words. Offer a single, low-friction call-to-action (CTA).
4. **Lead with unblocking business:** Frame the assessment as a tool to close enterprise deals, pass vendor security reviews, and satisfy customer compliance demands.

---

## 2. Channel A: Direct Outreach to SaaS Founders & CTOs

### Sequence 1: The "Enterprise Deal Unblocker" (Email / LinkedIn)

**Target:** Seed to Series A/B B2B SaaS Founders or CTOs.  
**Trigger:** Company announces a new funding round, new enterprise feature, or expansion.

#### Message 1 (Day 1) — Initial Outreach
```text
Subject: Quick question regarding [Company Name]'s API security / vendor reviews

Hi [First Name],

Congrats on the recent launch of [Product/Feature]!

As you start selling to larger enterprise customers, one of the biggest friction points is usually the enterprise vendor security questionnaire—specifically proving that your public APIs and web portals have undergone independent security verification.

I run FELIX Security, an evidence-first offensive security auditing practice. We conduct non-destructive external web and API assessments that give your engineers exact, reproducible curl commands for any flaws found, plus a clean Letter of Attestation your sales team can share with enterprise buyers.

We are currently offering a fixed-price validation pilot (₹15,000–₹25,000) for select Indian SaaS companies.

Would you be open to a 15-minute intro call this Thursday at 3 PM to see if this fits your current engineering roadmap?

Best regards,

Jothish
Founder & Lead Assessor, FELIX Security
[Phone] | [LinkedIn Profile]
```

#### Message 2 (Day 4) — Value Follow-Up
```text
Subject: Re: Quick question regarding [Company Name]'s API security / vendor reviews

Hi [First Name],

Following up briefly on my note.

Most scanners dump 50-page PDF reports filled with false positives that frustrate developers. Our approach is strictly evidence-first: we only report verified defects with ready-to-run curl commands and code diffs, followed by a complimentary retest once your team deploys the fixes.

If you have 10 minutes this week, I’d be glad to share an example sanitized report so you can evaluate the depth of our findings.

Best,
Jothish
```

#### Message 3 (Day 9) — Graceful Breakaway
```text
Subject: Closing the loop / [Company Name] security

Hi [First Name],

I know you're laser-focused on scaling [Company Name], so I'll assume timing isn't right for an external security audit right now.

If you ever run into an enterprise customer demanding a third-party penetration testing report or attestation letter to unblock a contract, feel free to reach back out.

Wishing you and the team continued success!

Best,
Jothish
```

---

## 3. Channel B: Agency & Consultancy Partnerships

**Target:** Founders and Managing Directors of Web/Mobile Development Agencies and IT Consultancies.  
**Value Proposition:** Expand agency revenue by offering independent security audits to their clients as a white-label or referral partner.

#### Outreach Message (Email / LinkedIn)
```text
Subject: Partnering on security audits for [Agency Name]'s client projects

Hi [First Name],

I noticed the high-caliber web and mobile applications [Agency Name] builds for clients in [fintech / healthcare / SaaS].

When clients prepare to launch, they often ask: "Has this been independently penetration-tested?" Building an in-house security auditing team is expensive and distracting for a development agency.

I run FELIX Security. We partner with select engineering agencies to provide independent, non-destructive Web & API security assessments for client launches. 

We provide:
1. Exact, reproducible vulnerability reports that make your developers' lives easy (with direct code diffs).
2. A formal Letter of Attestation that gives your agency's clients total confidence at launch.
3. Flexible collaboration: either a 15% referral fee or transparent subcontracting.

Would you be open to a brief chat next week to discuss how we can add security audits to your client proposals?

Best regards,

Jothish
Founder & Lead Assessor, FELIX Security
```

---

## 4. Discovery Call Script (15–20 Minute Qualification)

```text
[Minutes 0–3: Rapport & Context]
- "Thanks for taking the time, [First Name]. I follow what you're building at [Company]..."
- "My goal today is simple: understand your current architecture and security roadmap, see if our external assessment is a good fit, and answer any technical questions."

[Minutes 3–8: Discovery Questions]
1. "What does your external attack surface look like today? (e.g., Single Page App, REST/GraphQL API gateway, mobile apps?)"
2. "Are you currently dealing with enterprise customers or compliance frameworks (SOC 2, ISO 27001, DPDP) that require independent third-party audits?"
3. "When was the last time you had an external security review performed? How was that experience for your developers?"
4. "What is your deployment cadence, and how quickly can your team action security fixes?"

[Minutes 8–15: Solution Alignment]
- "Here is how we work: We don't run automated scanners that spam you with theoretical warnings. We run FELIX—our proprietary engine—with manual technical verification."
- "You get reproducible curl commands, exact parameter locations, and a direct review call with me."
- "Once your team fixes the findings, we re-test for free and issue your Letter of Attestation."

[Minutes 15–20: Close & Next Step]
- "If you're ready, I can send over our standard Rules of Engagement and a 1-page proposal for a validation pilot on [agreed target]."
- "Can you confirm the email address where I should send the proposal?"
```

---

## 5. Objection Handling Guide

### Objection 1: "We already use an automated scanner (e.g. Snyk, Dependabot, SonarQube)."
> **Response:**  
> *"Those are fantastic tools for software composition analysis and linting source code. However, they only inspect static code. They cannot test runtime authorization flaws—like whether User A can access User B's billing records via an IDOR in your production API. That is where an external assessment comes in: we test your actual running application exactly how an external adversary would."*

### Objection 2: "We have a Web Application Firewall (WAF) / Cloudflare in front."
> **Response:**  
> *"Cloudflare is great for DDoS protection and basic bot mitigation, but a WAF has no understanding of your business logic. If an API endpoint returns sensitive customer data because of a missing authorization check, the WAF will let the request straight through because it looks like valid HTTP traffic. Our assessment evaluates the underlying application logic."*

### Objection 3: "We don't have the budget for a ₹3–5 Lakh penetration test."
> **Response:**  
> *"That's exactly why we created our Validation Pilot tier at ₹15,000–₹25,000. Big consultancy firms charge huge fees because of heavy overhead and billable hours. Because we use FELIX—our own proprietary engine—we eliminate manual overhead while preserving rigorous, human-reviewed verification. It gives you enterprise-grade evidence at a price built for early-stage companies."*

### Objection 4: "Will this crash our production application?"
> **Response:**  
> *"No. Our methodology is strictly non-destructive. We do not perform volumetric DDoS attacks, memory exhaustion, or database write injections. Every test is rate-limited and read-only. Furthermore, we provide a custom HTTP header on all requests so your operations team can track our activity in real time, and we maintain an emergency contact line during testing."*
