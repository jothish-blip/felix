# FELIX CLI :: Zero-Network Reporting (`felix report`)

> **Module 04** | Offline report generation, zero-network guarantee, Commercial Report 2.0, SARIF export, and risk reconciliation.

---

## 1. Architectural Philosophy

One of FELIX's key architectural guarantees is **decoupled offline reporting**:

```text
┌───────────────────────┐
│      felix scan       │ ──► Executes network requests, crawling & evidence collection
└──────────┬────────────┘
           │ Output
           ▼
┌───────────────────────┐
│   scan-result.json    │ ──► Complete, self-contained, machine-readable audit state
└──────────┬────────────┘
           │
           │ (Air-gapped / Zero Network Activity)
           ▼
┌───────────────────────┐
│     felix report      │ ──► Parses saved JSON, formats HTML, SARIF, or updated JSON
└───────────────────────┘
```

When running `felix report`, FELIX:
- Makes **zero HTTP or DNS requests**.
- Does not contact any remote telemetry or update servers.
- Can be safely run in air-gapped environments, secure analyst enclaves, and CI/CD pipelines without internet access.

---

## 2. Command Syntax & Options

```bash
felix report <scan-result.json> [options]
```

### Supported Options:

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `-html <file>` | `--html` | — | Export standalone HTML assessment report. |
| `-json <file>` | `--json` | — | Export or re-serialize normalized JSON assessment report. |
| `-sarif <file>` | `--sarif` | — | Export OASIS SARIF 2.1.0 format report for CI/CD ingestion. |
| `-commercial` | `--commercial` | `false` | Render Commercial Report 2.0 specification with attack surface taxonomy. |
| `-silent` | `-s` | `false` | Suppress human-readable progress and banner output. |
| `-verbose` | `-v` | `false` | Display detailed breakdown of finding contributions and asset counts. |

---

## 3. Commercial Report 2.0 vs. Standard Report

FELIX supports two HTML report presentation templates:

### A. Standard Assessment Report (`-html report.html`)
- **Theme:** Pure-Black mode (`#000000`).
- **Focus:** Technical security audit findings, evidence inspection drawers, HTTP requests/responses, remediation guides.
- **Audience:** Security analysts, DevSecOps engineers, penetration testers.

### B. Commercial Report 2.0 (`-commercial -html commercial.html`)
- **Theme:** High-contrast commercial presentation with executive summary card.
- **Focus:** Enterprise attack surface taxonomy, relational asset intelligence (API routes, auth surfaces, forms, cloud dependencies), categorized risk bands, and prioritized executive remediation roadmaps.
- **Audience:** CISOs, security leaders, technical managers, external auditors.

---

## 4. Risk Score Reconciliation & Attribution

In FELIX reports, the overall risk score (0–100) is **fully explainable and mathematically reconciled**:
- Every contributing finding is explicitly listed with its raw finding score, confidence multiplier, and verification multiplier.
- Diminishing returns scaling prevents score inflation from repetitive low-severity findings.
- Defense-in-depth caps and negative evidence reductions (e.g. verified 401/403 authorization gates) are factored in.
- The displayed findings mathematically sum to the final calculated score.

When an assessment state is `BLOCKED` or `FAILED`, the risk score displays as `N/A` (`--`) across both terminal and generated reports to prevent inaccurate security posture assumptions.

---

## 5. Practical Learning Exercises

### Exercise 4.1: Generate Offline HTML from Existing JSON Baseline
Use an existing assessment artifact from `assessments/juice-shop/first-assessment.json`:
```powershell
.\bin\felix.exe report assessments\juice-shop\first-assessment.json -html offline-test.html
```
Verify the generated file:
```powershell
Test-Path offline-test.html
(Get-Item offline-test.html).Length
```

### Exercise 4.2: Generate Offline SARIF 2.1.0 from Scan JSON
```powershell
.\bin\felix.exe report assessments\juice-shop\first-assessment.json -sarif offline-test.sarif
```
Verify the SARIF structure:
```powershell
Get-Content offline-test.sarif -TotalCount 15
```

### Exercise 4.3: Generate Commercial Report 2.0 Specification
```powershell
.\bin\felix.exe report assessments\juice-shop\first-assessment.json -commercial -html commercial-test.html
```
Verify that the commercial report contains attack surface intelligence:
```powershell
Select-String -Path commercial-test.html -Pattern "Attack Surface"
```

### Exercise 4.4: Verify Zero-Network Execution
Unplug network access or run in an isolated firewall rule:
```powershell
# Notice the command completes instantaneously without any network dependency
.\bin\felix.exe report assessments\juice-shop\first-assessment.json -json re-serialized.json -s
```
Clean up temporary test files:
```powershell
Remove-Item offline-test.html, offline-test.sarif, commercial-test.html, re-serialized.json -ErrorAction SilentlyContinue
```
