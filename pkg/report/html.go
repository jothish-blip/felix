package report

import (
	"bytes"
	"html/template"
	"os"
)

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Felix Security Assessment Report — {{.Target}}</title>
<style>
  :root {
    --bg-main: #000000;
    --bg-surface: #0a0a0a;
    --bg-surface-elevated: #121212;
    --bg-surface-subtle: #181818;
    --border-subtle: #222222;
    --border-default: #2d2d2d;
    --border-strong: #3d3d3d;
    --text-primary: #f5f5f5;
    --text-secondary: #a3a3a3;
    --text-muted: #737373;

    --crit: #ef4444;
    --crit-bg: #1a0505;
    --crit-border: #7f1d1d;
    --high: #f97316;
    --high-bg: #1c0a00;
    --high-border: #7c2d12;
    --med: #f59e0b;
    --med-bg: #1c1200;
    --med-border: #78350f;
    --low: #3b82f6;
    --low-bg: #08152c;
    --low-border: #1d4ed8;
    --info: #94a3b8;
    --info-bg: #111827;
    --info-border: #334155;
    --verified: #10b981;
    --verified-bg: #022c22;
    --verified-border: #047857;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.55;
    padding: 2.5rem 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 1200px; margin: 0 auto; }

  header {
    border-bottom: 1px solid var(--border-default);
    padding-bottom: 2rem;
    margin-bottom: 2.5rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 1.5rem;
  }
  .brand-tag {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: var(--text-muted);
    font-weight: 700;
    margin-bottom: 0.35rem;
  }
  .header-title h1 {
    font-size: 2rem;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: -0.03em;
    line-height: 1.2;
  }
  .header-meta {
    margin-top: 0.6rem;
    color: var(--text-secondary);
    font-size: 0.9rem;
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    align-items: center;
  }
  .header-meta span strong { color: var(--text-primary); }

  .score-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.75rem;
    padding: 1.25rem 1.75rem;
    text-align: center;
    min-width: 220px;
  }
  .score-val {
    font-size: 2.75rem;
    font-weight: 900;
    line-height: 1;
    letter-spacing: -0.04em;
  }
  .score-lbl {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-secondary);
    margin-top: 0.4rem;
    font-weight: 600;
  }

  .color-CRITICAL { color: var(--crit); }
  .color-HIGH { color: var(--high); }
  .color-MEDIUM { color: var(--med); }
  .color-LOW { color: var(--low); }
  .color-INFORMATIONAL, .color-INFO { color: var(--info); }

  /* Sections */
  section { margin-bottom: 3rem; }
  h2 {
    font-size: 1.3rem;
    font-weight: 700;
    margin-bottom: 1.25rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border-subtle);
    color: #ffffff;
    letter-spacing: -0.02em;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h3 {
    font-size: 1.05rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.75rem;
  }

  /* Grid & Cards */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    padding: 1.25rem;
    transition: border-color 0.15s ease;
  }
  .card:hover { border-color: var(--border-strong); }
  .card-lbl {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
  }
  .card-val {
    font-size: 1.85rem;
    font-weight: 800;
    margin-top: 0.35rem;
    line-height: 1;
    color: #ffffff;
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 0.25rem 0.55rem;
    border-radius: 0.25rem;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    line-height: 1;
  }
  .badge-CRITICAL { background: var(--crit-bg); color: #fca5a5; border: 1px solid var(--crit-border); }
  .badge-HIGH { background: var(--high-bg); color: #fdba74; border: 1px solid var(--high-border); }
  .badge-MEDIUM { background: var(--med-bg); color: #fde047; border: 1px solid var(--med-border); }
  .badge-LOW { background: var(--low-bg); color: #93c5fd; border: 1px solid var(--low-border); }
  .badge-INFO { background: var(--info-bg); color: #cbd5e1; border: 1px solid var(--info-border); }

  .badge-VERIFIED { background: var(--verified-bg); color: #6ee7b7; border: 1px solid var(--verified-border); }
  .badge-CANDIDATE { background: var(--med-bg); color: #fde047; border: 1px solid var(--med-border); }
  .badge-INCONCLUSIVE { background: #141414; color: #a3a3a3; border: 1px solid #333333; }
  .badge-DETECTED { background: var(--med-bg); color: #fde047; border: 1px solid var(--med-border); }
  .badge-OBSERVED { background: #141414; color: #a3a3a3; border: 1px solid #333333; }
  .badge-NOT_VERIFIED { background: #171717; color: #d4d4d4; border: 1px solid #404040; }
  .badge-NOT_EXPOSED { background: #042f2e; color: #5eead4; border: 1px solid #0f766e; }

  /* Narrative Boxes */
  .summary-narrative {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }
  .summary-narrative p + p { margin-top: 0.75rem; }
  .summary-narrative strong { color: var(--text-primary); }

  /* Risk Bar */
  .risk-bar-container {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.5rem;
    padding: 1.25rem;
    margin-bottom: 2rem;
  }
  .risk-bar-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
    color: var(--text-secondary);
  }
  .risk-track {
    height: 10px;
    background-color: #1a1a1a;
    border-radius: 5px;
    overflow: hidden;
    position: relative;
  }
  .risk-fill {
    height: 100%;
    border-radius: 5px;
    transition: width 0.3s ease;
  }
  .risk-fill-CRITICAL { background: var(--crit); }
  .risk-fill-HIGH { background: var(--high); }
  .risk-fill-MEDIUM { background: var(--med); }
  .risk-fill-LOW { background: var(--low); }
  .risk-fill-INFORMATIONAL { background: var(--info); }

  /* Finding & Story Cards */
  .item-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
    transition: border-color 0.15s ease;
  }
  .item-card:hover { border-color: var(--border-strong); }
  .item-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.85rem;
    flex-wrap: wrap;
  }
  .item-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.3;
  }
  .item-meta {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
    word-break: break-all;
  }
  .item-meta strong { color: var(--text-primary); }

  .item-desc {
    font-size: 0.95rem;
    color: #d4d4d4;
    margin-bottom: 1rem;
    line-height: 1.55;
  }

  .code-snippet {
    background-color: #050505;
    border: 1px solid var(--border-subtle);
    border-radius: 0.35rem;
    padding: 0.85rem 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
    color: #e5e5e5;
    white-space: pre-wrap;
    word-break: break-all;
    margin-bottom: 0.85rem;
  }

  .verification-block {
    background-color: #06111e;
    border: 1px solid #102a45;
    border-radius: 0.35rem;
    padding: 0.75rem 1rem;
    font-size: 0.88rem;
    color: #93c5fd;
    margin-bottom: 0.85rem;
  }
  .verification-block strong { color: #bfdbfe; }

  .negative-block, .negative-evidence-box {
    background-color: #061414;
    border-left: 3px solid #14b8a6;
    border-radius: 0 0.35rem 0.35rem 0;
    padding: 0.65rem 0.95rem;
    font-size: 0.88rem;
    color: #5eead4;
    margin-bottom: 0.85rem;
  }
  .negative-block strong, .negative-evidence-box strong { color: #99f6e4; }

  .investigate-block {
    background-color: #160f24;
    border-left: 3px solid #a855f7;
    border-radius: 0 0.35rem 0.35rem 0;
    padding: 0.75rem 1rem;
    font-size: 0.9rem;
    color: #e9d5ff;
    margin-bottom: 0.85rem;
  }
  .investigate-block strong { color: #f3e8ff; }

  .remediation-block {
    background-color: #0a1120;
    border-left: 3px solid #3b82f6;
    border-radius: 0 0.35rem 0.35rem 0;
    padding: 0.75rem 1rem;
    font-size: 0.9rem;
    color: #bfdbfe;
  }
  .remediation-block strong { color: #dbeafe; }

  .story-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-left: 4px solid #38bdf8;
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
  }
  .story-list {
    padding-left: 1.25rem;
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin: 0.5rem 0 1rem 0;
  }
  .story-list li { margin-bottom: 0.35rem; }

  /* Interactive Filters */
  .filter-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
    margin-bottom: 1.25rem;
  }
  .filter-btn {
    background-color: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    padding: 0.4rem 0.75rem;
    border-radius: 0.25rem;
    font-size: 0.8rem;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.15s ease;
  }
  .filter-btn:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }
  .filter-btn.active {
    background-color: #262626;
    border-color: #525252;
    color: #ffffff;
  }
  .search-box {
    background-color: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-primary);
    padding: 0.4rem 0.75rem;
    border-radius: 0.25rem;
    font-size: 0.85rem;
    margin-left: auto;
    min-width: 220px;
    outline: none;
  }
  .search-box:focus {
    border-color: #525252;
  }

  /* Expandable Accordion */
  details {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    margin-bottom: 1rem;
    overflow: hidden;
  }
  summary {
    padding: 1rem 1.25rem;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.95rem;
    color: var(--text-primary);
    list-style: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
  }
  summary::-webkit-details-marker { display: none; }
  summary::after {
    content: "+";
    font-size: 1.2rem;
    color: var(--text-muted);
  }
  details[open] summary::after { content: "−"; }
  details[open] summary { border-bottom: 1px solid var(--border-subtle); }
  .details-body {
    padding: 1.25rem;
    font-size: 0.9rem;
    color: var(--text-secondary);
  }

  footer {
    border-top: 1px solid var(--border-default);
    padding-top: 2rem;
    margin-top: 3.5rem;
    text-align: center;
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
  @media print {
    body { background: #ffffff; color: #000000; padding: 0; }
    .card, .item-card, .story-card, .summary-narrative, details {
      background: #ffffff; color: #000000; border: 1px solid #cccccc;
    }
    .score-card { background: #f0f0f0; border: 1px solid #cccccc; }
    .filter-bar { display: none; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- 1. Report Header -->
  <header>
    <div class="header-title">
      <div class="brand-tag">Felix Security Auditor</div>
      <h1>FELIX SECURITY AUDIT REPORT</h1>
      <div class="header-meta">
        <span>Target: <strong>{{.Target}}</strong></span>
        <span>Generated: <strong>{{.Timestamp}}</strong></span>
        {{if .Duration}}<span>Duration: <strong>{{.Duration}}</strong></span>{{else if .DurationMs}}<span>Duration: <strong>{{.DurationMs}}ms</strong></span>{{end}}
        <span>Version: <strong>Felix {{.Version}}</strong></span>
      </div>
    </div>
    <div class="score-card">
      <div class="score-val color-{{.RiskLevel}}">{{.RiskScore}}</div>
      <div class="score-lbl">Felix Risk Score ({{.RiskLevel}})</div>
    </div>
  </header>

  <!-- 2. Executive Summary -->
  <section>
    <h2>Executive Summary</h2>
    <div class="summary-narrative">
      <p>
        Felix completed an automated defensive security audit of <strong>{{.Target}}</strong>.
        {{if eq .RiskScore 0}}
        No active vulnerabilities, leaked credentials, or missing security baselines were observed during the audit.
        {{else if le .RiskScore 20}}
        The target maintains a secure baseline posture with <strong>{{.RiskLevel}}</strong> overall risk ({{.RiskScore}}/100).
        Identified findings represent defense-in-depth hardening opportunities (such as web application security headers) and passive endpoint inventory observations.
        {{else if le .RiskScore 59}}
        The target exhibited <strong>{{.RiskLevel}}</strong> risk ({{.RiskScore}}/100). Important exposures or informational disclosures warrant prompt administrative review.
        {{else}}
        The target exhibited <strong>{{.RiskLevel}}</strong> risk ({{.RiskScore}}/100). High-impact security conditions or exposed infrastructure credentials were confirmed and require immediate remediation.
        {{end}}
      </p>
      {{if .TopPriorities}}
      <p>
        <strong>Primary Focus:</strong> Immediate investigation should prioritize <em>{{(index .TopPriorities 0).Title}}</em> at <code>{{(index .TopPriorities 0).Endpoint}}</code>.
      </p>
      {{end}}
    </div>

    <!-- 3. Risk Meter -->
    <div class="risk-bar-container">
      <div class="risk-bar-header">
        <span>Felix Deterministic Risk Meter (0–100)</span>
        <span class="color-{{.RiskLevel}}"><strong>{{.RiskScore}} / 100 — {{.RiskLevel}}</strong></span>
      </div>
      <div class="risk-track">
        <div class="risk-fill risk-fill-{{.RiskLevel}}" style="width: {{.RiskScore}}%;"></div>
      </div>
      <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.5rem;">
        Note: The Felix Risk Score is a deterministic 0–100 exposure metric weighted by empirical verification, multi-exposure diminishing returns, and hardening caps. It is not CVSS.
      </div>
    </div>

    <!-- 4. Findings & Verification Breakdown Grid -->
    <div class="grid">
      <div class="card">
        <div class="card-lbl">Total Findings</div>
        <div class="card-val">{{.Summary.TotalFindings}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Critical</div>
        <div class="card-val color-CRITICAL">{{.Summary.CriticalCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">High</div>
        <div class="card-val color-HIGH">{{.Summary.HighCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Medium</div>
        <div class="card-val color-MEDIUM">{{.Summary.MediumCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Low & Info</div>
        <div class="card-val color-LOW">{{add .Summary.LowCount .Summary.InfoCount}}</div>
      </div>
    </div>

    <h3 style="font-size: 1rem; font-weight: 600; color: #d4d4d4; margin: 1.25rem 0 0.75rem 0;">Verification Breakdown</h3>
    <div class="grid">
      <div class="card">
        <div class="card-lbl">Verified Exposures</div>
        <div class="card-val" style="color: #6ee7b7;">{{.Summary.VerifiedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Detected Candidates</div>
        <div class="card-val" style="color: #fde047;">{{.Summary.DetectedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Observed Inventory</div>
        <div class="card-val" style="color: #93c5fd;">{{.Summary.ObservedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Defended / Protected</div>
        <div class="card-val" style="color: #5eead4;">{{.Summary.NotExposedCount}}</div>
      </div>
    </div>
  </section>

  <!-- 5. Investigate First -->
  {{if .TopPriorities}}
  <section>
    <h2>Investigate First (Actionable Priorities)</h2>
    {{range .TopPriorities}}
    <div class="item-card">
      <div class="item-header">
        <div class="item-title">{{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
          {{if .Verification.Status}}
          <span class="badge badge-{{.Verification.Status}}">{{.Verification.Status}}</span>
          {{end}}
        </div>
      </div>
      <div class="item-meta">
        <strong>Location:</strong> {{if .EvidenceDetails.Location}}{{.EvidenceDetails.Location}}{{else}}{{.Endpoint}}{{end}} ({{.Method}})
        &bull; <strong>Detection Method:</strong> {{if .EvidenceDetails.DetectionMethod}}{{.EvidenceDetails.DetectionMethod}}{{else}}{{.Source}}{{end}}
        &bull; <strong>Category:</strong> {{.Category}}
      </div>
      <div class="item-desc">{{.Description}}</div>

      {{if .Verification.Result}}
      <div class="verification-block">
        <strong>Verification Status ({{.Verification.Status}}):</strong> {{.Verification.Result}}
      </div>
      {{end}}

      {{if .EvidenceDetails.NegativeEvidence}}
      <div class="negative-block negative-evidence-box">
        <strong>Negative Evidence / Safety Verification:</strong> {{.EvidenceDetails.NegativeEvidence}}
      </div>
      {{end}}

      <div class="remediation-block">
        <strong>Action:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </section>
  {{end}}

  <!-- 6. Correlated Security Stories -->
  {{if .SecurityStories}}
  <section>
    <h2>Correlated Security Stories ({{len .SecurityStories}})</h2>
    {{range .SecurityStories}}
    <div class="story-card">
      <div class="item-header">
        <div class="item-title">{{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; align-items: center;">
          {{if .RiskContribution}}<span class="badge badge-INFO">+{{.RiskContribution}} Risk Pts</span>{{end}}
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
        </div>
      </div>
      {{if .Summary}}
      <p style="margin-bottom: 0.5rem; font-size: 0.95rem; font-weight: 600; color: #f5f5f5;">{{.Summary}}</p>
      {{end}}
      <p style="margin-bottom: 0.75rem; font-size: 0.9rem; color: #d4d4d4;">{{.Description}}</p>

      <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem;">Correlated Signals & Evidence:</div>
      <ul class="story-list">
        {{range .Evidence}}
        <li>{{.}}</li>
        {{end}}
      </ul>

      <div style="font-size: 0.85rem; font-weight: 600; color: #fca5a5; margin-bottom: 0.25rem;">Security Impact:</div>
      <p style="font-size: 0.9rem; margin-bottom: 0.85rem; color: #fecaca;">{{.Impact}}</p>

      {{if .InvestigateFirst}}
      <div class="investigate-block">
        <strong>Investigate First:</strong> {{.InvestigateFirst}}
      </div>
      {{end}}

      <div class="remediation-block">
        <strong>Remediation Guidance:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </section>
  {{end}}

  <!-- Correlated Attack Paths -->
  {{if .AttackPaths}}
  <section>
    <h2>Correlated Attack Paths ({{len .AttackPaths}})</h2>
    {{range .AttackPaths}}
    <div class="story-card" style="border-left-color: {{if eq .Status "VERIFIED"}}#10b981{{else if eq .Status "CANDIDATE"}}#f59e0b{{else}}#6b7280{{end}};">
      <div class="item-header">
        <div class="item-title">{{if .SyntheticFixture}}<span class="badge badge-INFO">[SYNTHETIC FIXTURE]</span> {{end}}{{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap;">
          <span class="badge badge-{{.Status}}">{{.Status}}</span>
          <span class="badge badge-{{.CombinedRiskLevel}}">{{.CombinedRiskLevel}} ({{.CombinedRiskScore}}/100)</span>
          <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
        </div>
      </div>

      <div class="item-meta">
        <strong>Target Asset:</strong> {{.TargetAsset}}
        {{if .EntryPoint}}&bull; <strong>Entry Point:</strong> {{.EntryPoint}}{{end}}
        &bull; <strong>Primary Weakness:</strong> {{.PrimaryWeakness}}
      </div>

      <div style="font-size: 0.85rem; font-weight: 600; color: #fca5a5; margin-bottom: 0.25rem;">Terminal Impact:</div>
      <p style="font-size: 0.9rem; margin-bottom: 0.75rem; color: #fecaca;">{{.TerminalImpact}}</p>

      {{if .RiskRationale}}
      <p style="font-size: 0.88rem; color: #d4d4d4; margin-bottom: 0.75rem;"><strong>Risk Rationale:</strong> {{.RiskRationale}}</p>
      {{end}}

      {{if .Transitions}}
      <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem;">Validated Transition Sequence:</div>
      <ul class="story-list">
        {{range .Transitions}}
        <li>{{.}}</li>
        {{end}}
      </ul>
      {{end}}

      {{if .Assumptions}}
      <div style="font-size: 0.85rem; font-weight: 600; color: #fde047; margin-bottom: 0.25rem;">Preconditions & Assumptions:</div>
      <ul class="story-list">
        {{range .Assumptions}}
        <li>{{.}}</li>
        {{end}}
      </ul>
      {{end}}

      {{if .MissingEvidence}}
      <div class="negative-block" style="margin-bottom: 0.75rem;">
        <strong>Missing Evidence / Verification Gaps:</strong>
        <ul style="padding-left: 1.25rem; margin-top: 0.25rem;">
          {{range .MissingEvidence}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}

      {{if .Remediation}}
      <div class="remediation-block">
        <strong>Choke Point Remediation:</strong> {{.Remediation}}
      </div>
      {{end}}
    </div>
    {{end}}
  </section>
  {{end}}

  <!-- 7. Detailed Findings Inventory -->
  <section>
    <h2>Detailed Findings Inventory ({{len .Findings}})</h2>

    <!-- Interactive Filters -->
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('all')">All ({{len .Findings}})</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({{.Summary.CriticalCount}})</button>
      <button class="filter-btn" onclick="filterFindings('HIGH')">High ({{.Summary.HighCount}})</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({{.Summary.MediumCount}})</button>
      <button class="filter-btn" onclick="filterFindings('LOW')">Low ({{.Summary.LowCount}})</button>
      <button class="filter-btn" onclick="filterFindings('INFO')">Info ({{.Summary.InfoCount}})</button>
      <button class="filter-btn" onclick="filterFindings('VERIFIED')">Verified ({{.Summary.VerifiedCount}})</button>
      <input type="text" class="search-box" id="findingSearch" placeholder="Search findings..." onkeyup="searchFindings()">
    </div>

    <div id="findingsContainer">
      {{if not .Findings}}
      <div class="card" style="text-align: center; padding: 2.5rem; color: var(--text-secondary);">
        No security findings detected on this target.
      </div>
      {{end}}

      {{range .Findings}}
      <div class="item-card finding-item" data-severity="{{.Severity}}" data-verification="{{.Verification.Status}}">
        <div class="item-header">
          <div class="item-title">[{{.ID}}] {{.Title}}</div>
          <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
            <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
            <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
            {{if .Verification.Status}}
            <span class="badge badge-{{.Verification.Status}}">{{.Verification.Status}}</span>
            {{end}}
          </div>
        </div>
        <div class="item-meta">
          <strong>Location:</strong> {{if .EvidenceDetails.Location}}{{.EvidenceDetails.Location}}{{else}}{{.Endpoint}}{{end}} ({{.Method}})
          &bull; <strong>Detection:</strong> {{if .EvidenceDetails.DetectionMethod}}{{.EvidenceDetails.DetectionMethod}}{{else}}{{.Source}}{{end}}
          &bull; <strong>Category:</strong> {{.Category}}
        </div>
        <div class="item-desc">{{.Description}}</div>

        {{if .Verification.Result}}
        <div class="verification-block">
          <strong>Verification Status ({{.Verification.Status}}):</strong> {{.Verification.Result}}
        </div>
        {{end}}

        {{if .Evidence}}
        <div class="code-snippet">{{.Evidence}}</div>
        {{end}}

        {{if .EvidenceDetails.NegativeEvidence}}
        <div class="negative-block negative-evidence-box">
          <strong>Negative Evidence / Safety Verification:</strong> {{.EvidenceDetails.NegativeEvidence}}
        </div>
        {{end}}

        <div class="remediation-block">
          <strong>Remediation:</strong> {{.Remediation}}
        </div>
      </div>
      {{end}}
    </div>
  </section>

  <!-- 8. Technical Details & Scope -->
  <section>
    <h2>Assessment Methodology & Technical Scope</h2>

    <details>
      <summary>Methodology & Analysis Pipeline</summary>
      <div class="details-body">
        <p>Felix follows an evidence-first, non-destructive web security auditing methodology across six sequential phases:</p>
        <ol style="padding-left: 1.25rem; margin-top: 0.5rem; line-height: 1.6;">
          <li><strong>Asset Discovery:</strong> Systematic ingestion of client HTML, JavaScript chunks, stylesheets, manifests, and production source maps within strict scope boundaries.</li>
          <li><strong>Secret Intelligence:</strong> Shannon entropy evaluation combined with structured alphabet filtering, regular expressions, and context weighting to identify high-entropy secrets and exposed service keys.</li>
          <li><strong>Cloud & BaaS Analysis:</strong> Detection and bounded, non-destructive verification of cloud backends (Supabase, Firebase, AWS S3, Google Cloud Storage).</li>
          <li><strong>API Security Auditing:</strong> Extraction of REST and GraphQL routes from client code, classification of endpoint taxonomy, evaluation of authentication barriers (401/403/404), and inspection of defensive response headers.</li>
          <li><strong>Evidence Verification:</strong> Empirical corroboration distinguishing Discovery &rarr; Detection &rarr; Verification &rarr; Assessment to eliminate false positives.</li>
          <li><strong>Risk Assessment & Reporting:</strong> Deterministic 0–100 Felix Risk Scoring, correlation of multi-signal security stories, deduplication, and automated secret redaction.</li>
        </ol>
      </div>
    </details>

    <details>
      <summary>Scope, Safety Controls & Non-Destructive Guarantee</summary>
      <div class="details-body">
        <ul style="padding-left: 1.25rem; line-height: 1.6;">
          <li><strong>Non-Destructive Probing:</strong> Felix conducts passive analysis and safe, read-only HTTP GET/HEAD checks. It never submits destructive payloads, database mutations, or SQL injections.</li>
          <li><strong>Zero Credential Transmission:</strong> Privileged credentials or tokens discovered in client assets are strictly NEVER transmitted to provider APIs or used for administrative probing.</li>
          <li><strong>Scope Adherence:</strong> All requests strictly enforce the configured scope (e.g. same-origin) and disallow out-of-scope asset crawling.</li>
          <li><strong>Bounded Resource Controls:</strong> Timeouts (10s default), response caps (10MB default), and rate-limit backoff (HTTP 429) prevent denial-of-service risks.</li>
        </ul>
      </div>
    </details>

    <details>
      <summary>Limitations & Disclaimer</summary>
      <div class="details-body">
        <p>Felix is a bounded black-box security auditing tool designed to evaluate client-accessible attack surfaces and configuration posture. It does not perform invasive vulnerability exploitation, authenticated session hijacking, or internal network penetration. Findings reflect observations made at the scan timestamp and require human engineering review before deployment decisions.</p>
      </div>
    </details>
  </section>

  <!-- Footer -->
  <footer>
    <p>Generated by <strong>Felix Security Auditor</strong> &bull; Professional, evidence-first web security auditing.</p>
  </footer>

</div>

<script>
  function filterFindings(sev) {
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    const items = document.querySelectorAll('.finding-item');
    items.forEach(item => {
      if (sev === 'all') {
        item.style.display = 'block';
      } else if (sev === 'VERIFIED') {
        item.style.display = item.getAttribute('data-verification') === 'VERIFIED' ? 'block' : 'none';
      } else {
        item.style.display = item.getAttribute('data-severity') === sev ? 'block' : 'none';
      }
    });
  }

  function searchFindings() {
    const query = document.getElementById('findingSearch').value.toLowerCase();
    const items = document.querySelectorAll('.finding-item');
    items.forEach(item => {
      const text = item.innerText.toLowerCase();
      item.style.display = text.includes(query) ? 'block' : 'none';
    });
  }
</script>
</body>
</html>`

// GenerateHTML renders the sanitized audit report into a standalone, offline HTML document.
func GenerateHTML(rep Report) (string, error) {
	sanitized := SanitizeReport(rep)

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("felix-report").Funcs(funcMap).Parse(htmlReportTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, sanitized); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WriteHTML writes the self-contained HTML report to disk.
func WriteHTML(rep Report, filePath string) error {
	content, err := GenerateHTML(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(content), 0644)
}
