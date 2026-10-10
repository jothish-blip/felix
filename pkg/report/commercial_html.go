package report

import (
	"bytes"
	"html/template"
	"os"
)

const commercialHTMLReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Felix Commercial Security Assessment Report — {{.ExecutiveSummary.Target}}</title>
<style>
  :root {
    --bg-main: #0a0e17;
    --bg-surface: #111827;
    --bg-surface-elevated: #1f2937;
    --bg-surface-subtle: #162032;
    --border-subtle: #1e293b;
    --border-default: #334155;
    --border-strong: #475569;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;

    --crit: #ef4444;
    --crit-bg: #450a0a;
    --crit-border: #991b1b;
    --high: #f97316;
    --high-bg: #431407;
    --high-border: #9a3412;
    --med: #f59e0b;
    --med-bg: #451a03;
    --med-border: #b45309;
    --low: #3b82f6;
    --low-bg: #172554;
    --low-border: #1d4ed8;
    --info: #06b6d4;
    --info-bg: #083344;
    --info-border: #0e7490;

    --verified: #10b981;
    --verified-bg: #064e3b;
    --verified-border: #059669;
    --detected: #eab308;
    --detected-bg: #422006;
    --detected-border: #ca8a04;
    --not-verified: #94a3b8;
    --not-verified-bg: #1e293b;
    --not-verified-border: #475569;
    --not-exposed: #06b6d4;
    --not-exposed-bg: #083344;
    --not-exposed-border: #0891b2;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2.5rem 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 1240px; margin: 0 auto; }

  header {
    border-bottom: 2px solid var(--border-default);
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
    font-size: 2.2rem;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: -0.03em;
    line-height: 1.2;
  }
  .header-meta {
    margin-top: 0.75rem;
    color: var(--text-secondary);
    font-size: 0.92rem;
    display: flex;
    flex-wrap: wrap;
    gap: 1.25rem;
    align-items: center;
  }
  .header-meta span strong { color: var(--text-primary); }

  .score-card {
    background-color: var(--bg-surface);
    border: 2px solid var(--border-default);
    border-radius: 0.75rem;
    padding: 1.25rem 2rem;
    text-align: center;
    min-width: 240px;
  }
  .score-val { font-size: 3rem; font-weight: 900; line-height: 1; margin-bottom: 0.35rem; }
  .score-lbl { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); font-weight: 700; }

  nav.toc {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 0.75rem;
    padding: 1.25rem 1.75rem;
    margin-bottom: 2.5rem;
  }
  .toc-title { font-size: 0.95rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 0.75rem; }
  .toc-links { display: flex; flex-wrap: wrap; gap: 0.75rem 1.5rem; }
  .toc-links a { color: var(--low); text-decoration: none; font-size: 0.92rem; font-weight: 600; }
  .toc-links a:hover { text-decoration: underline; color: #60a5fa; }

  section { margin-bottom: 3.5rem; }
  h2 {
    font-size: 1.5rem;
    font-weight: 800;
    color: #ffffff;
    border-bottom: 1px solid var(--border-default);
    padding-bottom: 0.6rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  h3 { font-size: 1.15rem; font-weight: 700; color: #f1f5f9; margin: 1.5rem 0 0.85rem 0; }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 0.65rem;
    padding: 1.1rem 1.35rem;
  }
  .card-lbl { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); font-weight: 700; margin-bottom: 0.35rem; }
  .card-val { font-size: 1.75rem; font-weight: 800; }

  .narrative-box {
    background-color: var(--bg-surface);
    border-left: 4px solid var(--low);
    border-radius: 0 0.5rem 0.5rem 0;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
  }
  .narrative-box p { margin-bottom: 0.6rem; }
  .narrative-box p:last-child { margin-bottom: 0; }

  .notice-box {
    background-color: var(--bg-surface-subtle);
    border: 1px solid var(--border-default);
    border-radius: 0.5rem;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
    font-size: 0.88rem;
    color: var(--text-secondary);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.55rem;
    border-radius: 0.35rem;
    font-size: 0.72rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border: 1px solid transparent;
  }
  .badge-CRITICAL { background: var(--crit-bg); color: var(--crit); border-color: var(--crit-border); }
  .badge-HIGH { background: var(--high-bg); color: var(--high); border-color: var(--high-border); }
  .badge-MEDIUM { background: var(--med-bg); color: var(--med); border-color: var(--med-border); }
  .badge-LOW { background: var(--low-bg); color: #93c5fd; border-color: var(--low-border); }
  .badge-INFO { background: var(--info-bg); color: #67e8f9; border-color: var(--info-border); }
  .badge-VERIFIED { background: var(--verified-bg); color: #6ee7b7; border-color: var(--verified-border); }
  .badge-DETECTED { background: var(--detected-bg); color: #fde047; border-color: var(--detected-border); }
  .badge-NOT_VERIFIED { background: var(--not-verified-bg); color: #cbd5e1; border-color: var(--not-verified-border); }
  .badge-OBSERVED { background: #1e1b4b; color: #a5b4fc; border-color: #4338ca; }
  .badge-NOT_EXPOSED { background: var(--not-exposed-bg); color: #67e8f9; border-color: var(--not-exposed-border); }
  .badge-SYNTHETIC { background: #581c87; color: #e9d5ff; border-color: #7e22ce; }

  .color-CRITICAL { color: var(--crit); }
  .color-HIGH { color: var(--high); }
  .color-MEDIUM { color: var(--med); }
  .color-LOW { color: #60a5fa; }
  .color-INFORMATIONAL, .color-INFO { color: #38bdf8; }

  .item-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 0.75rem;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .item-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .item-title { font-size: 1.15rem; font-weight: 700; color: #ffffff; }
  .item-meta {
    font-size: 0.88rem;
    color: var(--text-secondary);
    margin-bottom: 1rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem 1.5rem;
    background: var(--bg-surface-elevated);
    padding: 0.6rem 0.85rem;
    border-radius: 0.4rem;
  }
  .item-desc { font-size: 0.95rem; margin-bottom: 1.25rem; }

  .sub-box {
    background: var(--bg-surface-subtle);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
  }
  .sub-box-title {
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
  }

  .impact-box {
    background: #18181b;
    border-left: 4px solid var(--crit);
    border-radius: 0 0.5rem 0.5rem 0;
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
    font-size: 0.92rem;
  }
  .impact-title { font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: #fca5a5; margin-bottom: 0.4rem; }

  .code-snippet {
    background: #030712;
    border: 1px solid #1f2937;
    border-radius: 0.4rem;
    padding: 0.75rem 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
    color: #e2e8f0;
    overflow-x: auto;
    word-break: break-all;
    margin-top: 0.4rem;
  }

  table.data-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1.5rem;
    font-size: 0.88rem;
  }
  table.data-table th, table.data-table td {
    padding: 0.65rem 0.85rem;
    text-align: left;
    border-bottom: 1px solid var(--border-subtle);
  }
  table.data-table th {
    background: var(--bg-surface-elevated);
    color: var(--text-secondary);
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
  }
  table.data-table tr:hover td { background: var(--bg-surface-subtle); }

  .risk-track {
    background: var(--bg-surface-elevated);
    border-radius: 9999px;
    height: 12px;
    overflow: hidden;
    margin: 0.5rem 0;
  }
  .risk-fill { height: 100%; border-radius: 9999px; }
  .risk-fill-CRITICAL { background: var(--crit); }
  .risk-fill-HIGH { background: var(--high); }
  .risk-fill-MEDIUM { background: var(--med); }
  .risk-fill-LOW { background: var(--low); }
  .risk-fill-INFORMATIONAL { background: var(--info); }

  footer {
    border-top: 1px solid var(--border-default);
    padding-top: 2rem;
    margin-top: 4rem;
    font-size: 0.85rem;
    color: var(--text-muted);
    text-align: center;
  }

  @media print {
    body { background: #ffffff; color: #000000; padding: 0; }
    .card, .item-card, .narrative-box, .sub-box, .notice-box {
      background: #ffffff; color: #000000; border: 1px solid #cccccc;
    }
    .score-card { background: #f0f0f0; border: 1px solid #cccccc; }
    nav.toc { display: none; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header>
    <div class="header-title">
      <div class="brand-tag">Felix Security Auditor &bull; Commercial Report 2.0</div>
      <h1>FELIX SECURITY AUDIT REPORT</h1>
      <div class="header-meta">
        <span>Target: <strong>{{.ExecutiveSummary.Target}}</strong></span>
        <span>Assessment Ref: <strong>{{.ExecutiveSummary.AssessmentID}}</strong></span>
        <span>Generated: <strong>{{.GeneratedAt}}</strong></span>
        <span>Schema Version: <strong>v{{.SchemaVersion}}</strong></span>
      </div>
    </div>
    <div class="score-card">
      {{if or (eq .ExecutiveSummary.CompletionStatus "BLOCKED") (eq .ExecutiveSummary.CompletionStatus "FAILED") (eq .RiskOverview.RiskLevel "UNAVAILABLE")}}
      <div class="score-val" style="color: #ef4444;">N/A</div>
      <div class="score-lbl">ASSESSMENT {{if eq .ExecutiveSummary.CompletionStatus "BLOCKED"}}BLOCKED{{else if eq .ExecutiveSummary.CompletionStatus "FAILED"}}FAILED{{else}}UNAVAILABLE{{end}}</div>
      {{else}}
      <div class="score-val color-{{.RiskOverview.RiskLevel}}">{{.RiskOverview.RiskScore}}</div>
      <div class="score-lbl">Felix Risk Score ({{.RiskOverview.RiskLevel}})</div>
      {{end}}
    </div>
  </header>

  <!-- Table of Contents -->
  <nav class="toc">
    <div class="toc-title">Report Navigation</div>
    <div class="toc-links">
      <a href="#section-exec-summary">1. Executive Summary</a>
      <a href="#section-scope">2. Assessment Scope</a>
      <a href="#section-attack-surface">3. Attack Surface</a>
      <a href="#section-risk-overview">4. Risk Overview</a>
      <a href="#section-verified">5. Verified Findings ({{len .VerifiedFindings}})</a>
      <a href="#section-detected">6. Detected Findings ({{len .DetectedFindings}})</a>
      <a href="#section-observations">7. Observations ({{len .Observations}})</a>
      <a href="#section-appendix">8. Technical Appendix</a>
    </div>
  </nav>

  <!-- 1. Executive Summary -->
  <section id="section-exec-summary">
    <h2>1. Executive Summary</h2>
    {{if eq .ExecutiveSummary.CompletionStatus "BLOCKED"}}
    <div style="background: #200808; border: 1px solid #7f1d1d; border-radius: 0.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: #fca5a5;">
      <strong style="color: #ef4444; font-size: 1.05rem;">ASSESSMENT BLOCKED:</strong> Target presented access controls or automated challenge barriers (HTTP 403 / Cloudflare). Under Felix safe authorized audit rules, probes were halted. Security posture could not be evaluated.
    </div>
    {{else if eq .ExecutiveSummary.CompletionStatus "FAILED"}}
    <div style="background: #200808; border: 1px solid #7f1d1d; border-radius: 0.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: #fca5a5;">
      <strong style="color: #ef4444; font-size: 1.05rem;">ASSESSMENT FAILED:</strong> Target reachability could not be established due to network, transport, or server errors. Security posture could not be evaluated.
    </div>
    {{end}}
    <div class="narrative-box">
      <p><strong>Assessment Status:</strong> {{.ExecutiveSummary.CompletionStatus}} &bull; <strong>Scope:</strong> {{.ExecutiveSummary.ScopeSummary}}</p>
      <p>{{.ExecutiveSummary.PostureStatement}}</p>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-lbl">Total Assets Cataloged</div>
        <div class="card-val">{{.ExecutiveSummary.AssetsDiscoveredCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Verified Findings</div>
        <div class="card-val" style="color: #6ee7b7;">{{.ExecutiveSummary.FindingsVerifiedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Detected (Unverified)</div>
        <div class="card-val" style="color: #fde047;">{{.ExecutiveSummary.FindingsDetectedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Observations</div>
        <div class="card-val" style="color: #93c5fd;">{{.ExecutiveSummary.ObservationsCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Defended / Protected</div>
        <div class="card-val" style="color: #5eead4;">{{.ExecutiveSummary.NotExposedChecksCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Inconclusive Checks</div>
        <div class="card-val" style="color: #cbd5e1;">{{.ExecutiveSummary.InconclusiveChecksCount}}</div>
      </div>
    </div>

    {{if or .ExecutiveSummary.FrontendAssetsCount .ExecutiveSummary.APIEndpointsCount .ExecutiveSummary.WebRoutesCount}}
    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1.25rem; display: flex; flex-wrap: wrap; gap: 1rem;">
      {{if .ExecutiveSummary.FrontendAssetsCount}}<span>Frontend Assets Crawled: <strong>{{.ExecutiveSummary.FrontendAssetsCount}}</strong></span>{{end}}
      {{if .ExecutiveSummary.APIEndpointsCount}}<span>API Endpoints Cataloged: <strong>{{.ExecutiveSummary.APIEndpointsCount}}</strong></span>{{end}}
      {{if .ExecutiveSummary.WebRoutesCount}}<span>Web Routes Cataloged: <strong>{{.ExecutiveSummary.WebRoutesCount}}</strong></span>{{end}}
    </div>
    {{end}}

    <h3>Severity Distribution</h3>
    <div class="grid">
      <div class="card">
        <div class="card-lbl">Critical</div>
        <div class="card-val color-CRITICAL">{{index .ExecutiveSummary.SeverityDistribution "CRITICAL"}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">High</div>
        <div class="card-val color-HIGH">{{index .ExecutiveSummary.SeverityDistribution "HIGH"}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Medium</div>
        <div class="card-val color-MEDIUM">{{index .ExecutiveSummary.SeverityDistribution "MEDIUM"}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Low</div>
        <div class="card-val color-LOW">{{index .ExecutiveSummary.SeverityDistribution "LOW"}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Informational</div>
        <div class="card-val color-INFO">{{index .ExecutiveSummary.SeverityDistribution "INFO"}}</div>
      </div>
    </div>

    <h3>Key Evidence-Backed Concerns</h3>
    <ul style="padding-left: 1.25rem; line-height: 1.7; margin-bottom: 1.5rem;">
      {{range .ExecutiveSummary.KeyConcerns}}
      <li>{{.}}</li>
      {{end}}
    </ul>

    <h3>Assessment Limitations</h3>
    <ul style="padding-left: 1.25rem; line-height: 1.7; color: var(--text-secondary);">
      {{range .ExecutiveSummary.AssessmentLimitations}}
      <li>{{.}}</li>
      {{end}}
    </ul>
  </section>

  <!-- 2. Assessment Scope -->
  <section id="section-scope">
    <h2>2. Assessment Scope</h2>
    <div class="item-card">
      <div class="item-meta">
        <span>Provenance: <strong>{{.AssessmentScope.Provenance}}</strong></span>
        <span>Assessed Endpoints: <strong>{{.AssessmentScope.AssessedEndpointsCount}}</strong></span>
        <span>Discovered Endpoints: <strong>{{.AssessmentScope.DiscoveredEndpointsCount}}</strong></span>
        {{if .AssessmentScope.Duration}}<span>Duration: <strong>{{.AssessmentScope.Duration}}</strong></span>{{end}}
      </div>

      <div class="sub-box">
        <div class="sub-box-title">In-Scope Domains & URLs</div>
        <ul style="padding-left: 1.25rem;">
          {{range .AssessmentScope.InScopeURLs}}
          <li><code>{{.}}</code></li>
          {{end}}
        </ul>
      </div>

      {{if .AssessmentScope.AuthenticationContexts}}
      <div class="sub-box">
        <div class="sub-box-title">Authentication Contexts Evaluated</div>
        <ul style="padding-left: 1.25rem;">
          {{range .AssessmentScope.AuthenticationContexts}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}

      <div class="sub-box">
        <div class="sub-box-title">Engines Executed</div>
        <p style="font-size: 0.9rem;">{{range $i, $e := .AssessmentScope.EnginesExecuted}}{{if $i}}, {{end}}<code>{{$e}}</code>{{end}}</p>
      </div>

      {{if .AssessmentScope.ExplicitRestrictions}}
      <div class="sub-box">
        <div class="sub-box-title">Explicit Scope Restrictions</div>
        <ul style="padding-left: 1.25rem;">
          {{range .AssessmentScope.ExplicitRestrictions}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
  </section>

  <!-- 3. Attack Surface -->
  <section id="section-attack-surface">
    <h2>3. Attack Surface</h2>
    <p style="color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.92rem;">
      Discovered assets cataloged across crawler, API, secrets, and cloud inspection engines. Discovery of an endpoint or asset does not imply that it is vulnerable.
    </p>

    <table class="data-table">
      <thead>
        <tr>
          <th>Asset ID</th>
          <th>Asset Type</th>
          <th>URL / Location</th>
          <th>Source</th>
          <th>State</th>
          <th>HTTP Status</th>
        </tr>
      </thead>
      <tbody>
        {{range .AttackSurface.Assets}}
        <tr>
          <td><code>{{.AssetID}}</code></td>
          <td><span class="badge badge-INFO">{{.AssetType}}</span></td>
          <td><code>{{.URL}}</code></td>
          <td>{{.DiscoverySource}}</td>
          <td>{{.AssessmentState}}</td>
          <td>{{if .HTTPStatus}}{{.HTTPStatus}}{{else}}—{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </section>

  <!-- 4. Risk Overview -->
  <section id="section-risk-overview">
    <h2>4. Risk Overview</h2>
    <div class="narrative-box">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <span style="font-weight: 700;">Felix Deterministic Risk Meter (0–100)</span>
        <span class="color-{{.RiskOverview.RiskLevel}}"><strong>{{.RiskOverview.RiskScore}} / 100 — {{.RiskOverview.RiskLevel}}</strong></span>
      </div>
      <div class="risk-track">
        <div class="risk-fill risk-fill-{{.RiskOverview.RiskLevel}}" style="width: {{.RiskOverview.RiskScore}}%;"></div>
      </div>
      <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.5rem;">
        {{.RiskOverview.ScoringModelDescription}}
      </p>
    </div>

    <h3>Mathematical Risk Score Attribution</h3>
    <div class="sub-box" style="margin-bottom: 1.25rem;">
      <div style="font-size: 0.9rem; font-weight: 700; color: #f1f5f9; margin-bottom: 0.35rem;">Formula Reconciliation</div>
      <code style="font-size: 0.88rem; color: #38bdf8;">{{.RiskOverview.ScoreBreakdown.Formula}}</code>
      <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.35rem;">
        Deterministic diminishing returns weights: 1.0&times; (1st), 0.5&times; (2nd), 0.3&times; (3rd), 0.2&times; (4th), 0.1&times; (subsequent). Hardening subtotal capped at 20.0 max. Correlated story bonuses capped at +15 max.
      </div>
    </div>

    {{if .RiskOverview.FindingRiskContributions}}
    <table class="data-table">
      <thead>
        <tr>
          <th>Finding Ref</th>
          <th>Title</th>
          <th>Type</th>
          <th>Status</th>
          <th>Severity</th>
          <th style="text-align: right;">Raw Score</th>
          <th style="text-align: right;">Weight</th>
          <th style="text-align: right;">Adjusted Contribution</th>
        </tr>
      </thead>
      <tbody>
        {{range .RiskOverview.FindingRiskContributions}}
        <tr>
          <td><code>{{.FindingID}}</code></td>
          <td>{{.Title}}</td>
          <td><span class="badge badge-INFO">{{.RiskType}}</span></td>
          <td><span class="badge badge-{{.VerificationStatus}}">{{.VerificationStatus}}</span></td>
          <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
          <td style="text-align: right; font-weight: 600;">{{.Score}}</td>
          <td style="text-align: right; color: var(--text-secondary);">{{printf "%.1fx" .Weight}}</td>
          <td style="text-align: right; font-weight: 700; color: #6ee7b7;">{{printf "%.2f" .AdjustedScore}} pts</td>
        </tr>
        {{end}}
      </tbody>
      <tfoot>
        <tr style="font-weight: 700; background: var(--bg-surface-elevated);">
          <td colspan="7" style="text-align: right;">Exposure Subtotal:</td>
          <td style="text-align: right; color: #6ee7b7;">{{printf "%.2f" .RiskOverview.ScoreBreakdown.ExposureSubtotal}} pts</td>
        </tr>
        <tr style="font-weight: 700; background: var(--bg-surface-elevated);">
          <td colspan="7" style="text-align: right;">Hardening Subtotal (capped at 20):</td>
          <td style="text-align: right; color: #6ee7b7;">{{printf "%.2f" .RiskOverview.ScoreBreakdown.HardeningSubtotal}} pts</td>
        </tr>
        {{if gt .RiskOverview.ScoreBreakdown.StoryBonus 0.0}}
        <tr style="font-weight: 700; background: var(--bg-surface-elevated);">
          <td colspan="7" style="text-align: right;">Correlated Story Bonus:</td>
          <td style="text-align: right; color: #38bdf8;">+{{printf "%.2f" .RiskOverview.ScoreBreakdown.StoryBonus}} pts</td>
        </tr>
        {{end}}
        <tr style="font-weight: 800; font-size: 1rem; background: var(--bg-surface-subtle); border-top: 2px solid var(--border-default);">
          <td colspan="7" style="text-align: right;">Final Reconciled Score:</td>
          <td style="text-align: right; color: #ffffff;">{{.RiskOverview.ScoreBreakdown.TotalScore}} / 100</td>
        </tr>
      </tfoot>
    </table>
    {{end}}

    {{if .RiskOverview.AttackPaths}}
    <h3>Correlated Attack Paths ({{len .RiskOverview.AttackPaths}})</h3>
    {{range .RiskOverview.AttackPaths}}
    <div class="item-card">
      <div class="item-header">
        <div class="item-title">{{.Title}}</div>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <span class="badge badge-{{.CombinedRiskLevel}}">{{.CombinedRiskLevel}} ({{.CombinedRiskScore}}/100)</span>
          <span class="badge badge-INFO">{{.Status}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
        </div>
      </div>
      <p style="font-size: 0.92rem; margin-bottom: 0.75rem;">{{.RiskRationale}}</p>
      {{if .Transitions}}
      <div class="sub-box">
        <div class="sub-box-title">Attack Transitions</div>
        <ul style="padding-left: 1.25rem; font-size: 0.88rem;">
          {{range .Transitions}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
    {{end}}
    {{end}}

    {{if .RiskOverview.RiskConcentrations}}
    <h3>Risk Concentration by Component</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>Component</th>
          <th>Highest Risk Level</th>
          <th>Accumulated Score</th>
          <th>Finding Count</th>
        </tr>
      </thead>
      <tbody>
        {{range .RiskOverview.RiskConcentrations}}
        <tr>
          <td><code>{{.Component}}</code></td>
          <td><span class="badge badge-{{.RiskLevel}}">{{.RiskLevel}}</span></td>
          <td>{{.Score}}</td>
          <td>{{.Count}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{end}}
  </section>

  <!-- 5. Verified Findings -->
  <section id="section-verified">
    <h2>5. Verified Findings ({{len .VerifiedFindings}})</h2>
    <div class="notice-box">
      Verified findings represent empirical security conditions where mandatory verification policy criteria were satisfied under authorized, documented testing conditions.
    </div>

    {{if eq (len .VerifiedFindings) 0}}
    <p style="color: var(--text-muted); font-style: italic;">No verified findings were confirmed during this assessment.</p>
    {{else}}
    {{range .VerifiedFindings}}
    <div class="item-card finding-item" data-severity="{{.Severity}}" data-verification="VERIFIED">
      <div class="item-header">
        <div class="item-title">[{{.ID}}] {{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          <span class="badge badge-VERIFIED">VERIFIED</span>
          <span class="badge badge-INFO">Det Conf: {{.Confidence.DetectionConfidence}}</span>
          <span class="badge badge-INFO">Ver Conf: {{.Confidence.VerificationConfidence}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
        </div>
      </div>

      <div class="item-meta">
        <span><strong>Affected Asset:</strong> <code>{{.AffectedAsset}}</code></span>
        <span><strong>Location:</strong> <code>{{.AssetLocation}}</code></span>
        <span><strong>Auth Context:</strong> {{.AuthenticationState}}</span>
        <span><strong>Detection Method:</strong> {{.DetectionMethod}}</span>
        <span><strong>Risk Contribution:</strong> {{.RiskContribution.Score}}/40 ({{.RiskContribution.RiskType}})</span>
      </div>

      <div class="item-desc"><strong>Description:</strong> {{.Description}}</div>

      <div class="impact-box">
        <div class="impact-title">Security Impact Analysis</div>
        <p><strong>Demonstrated:</strong> {{.SecurityImpact.DemonstratedImpact}}</p>
        <p><strong>Plausible:</strong> {{.SecurityImpact.PlausibleImpact}}</p>
        <p><strong>Unverified Bounds:</strong> {{.SecurityImpact.UnverifiedImpact}}</p>
      </div>

      <div class="sub-box">
        <div class="sub-box-title">Empirical Verification Details [{{.Verification.MethodOrPolicy}}]</div>
        <p style="font-size: 0.9rem; margin-bottom: 0.5rem;">{{.Verification.ResultSummary}}</p>
        {{if .Verification.CriteriaSatisfied}}
        <div style="font-size: 0.85rem; color: #6ee7b7; margin-bottom: 0.4rem;">
          <strong>Criteria Satisfied:</strong> {{range $i, $c := .Verification.CriteriaSatisfied}}{{if $i}}, {{end}}{{$c}}{{end}}
        </div>
        {{end}}
        {{if .Verification.Limitations}}
        <div style="font-size: 0.85rem; color: var(--text-muted);">
          <strong>Verification Limitations:</strong> {{range $i, $l := .Verification.Limitations}}{{if $i}}, {{end}}{{$l}}{{end}}
        </div>
        {{end}}
      </div>

      <div class="sub-box">
        <div class="sub-box-title">Supporting Evidence (Sanitized)</div>
        <p style="font-size: 0.9rem;">{{.Evidence.Observation}}</p>
        {{if .Evidence.HTTPStatus}}
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
          HTTP Response Status: <strong>{{.Evidence.HTTPStatus}}</strong> {{if .Evidence.HTTPMethod}}({{.Evidence.HTTPMethod}}){{end}}
        </p>
        {{end}}
        {{if .Evidence.SafeCurlCommand}}
        <div style="margin-top: 0.5rem;">
          <span style="font-size: 0.78rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Safe Reproduction:</span>
          <div class="code-snippet">{{.Evidence.SafeCurlCommand}}</div>
        </div>
        {{end}}
      </div>
      {{if .Evidence.NegativeEvidence}}
      <div class="sub-box negative-evidence-box">
        <div class="sub-box-title">Negative Evidence / Safety Verification</div>
        <p style="font-size: 0.9rem;">{{.Evidence.NegativeEvidence}}</p>
      </div>
      {{end}}
    </div>
    {{end}}
    {{end}}
  </section>

  <!-- 6. Detected Findings -->
  <section id="section-detected">
    <h2>6. Detected Findings ({{len .DetectedFindings}})</h2>
    <div class="notice-box">
      Detected findings represent potential security weaknesses identified by heuristic or pattern detection whose empirical verification was not attempted, was inconclusive, or did not satisfy all mandatory policy criteria.
    </div>

    {{if eq (len .DetectedFindings) 0}}
    <p style="color: var(--text-muted); font-style: italic;">No unverified detected findings recorded.</p>
    {{else}}
    {{range .DetectedFindings}}
    <div class="item-card finding-item" data-severity="{{.Severity}}" data-verification="{{.Verification.Status}}">
      <div class="item-header">
        <div class="item-title">[{{.ID}}] {{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          <span class="badge badge-{{.Verification.Status}}">{{.Verification.Status}}</span>
          <span class="badge badge-INFO">Det Conf: {{.Confidence.DetectionConfidence}}</span>
          <span class="badge badge-INFO">Ver Conf: {{.Confidence.VerificationConfidence}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
        </div>
      </div>

      <div class="item-meta">
        <span><strong>Affected Asset:</strong> <code>{{.AffectedAsset}}</code></span>
        <span><strong>Auth Context:</strong> {{.AuthenticationState}}</span>
        <span><strong>Detection Method:</strong> {{.DetectionMethod}}</span>
        <span><strong>Risk Contribution:</strong> {{.RiskContribution.Score}}/40</span>
      </div>

      <div class="item-desc"><strong>Description:</strong> {{.Description}}</div>

      <div class="impact-box">
        <div class="impact-title">Security Impact Analysis</div>
        <p><strong>Demonstrated:</strong> {{.SecurityImpact.DemonstratedImpact}}</p>
        <p><strong>Plausible:</strong> {{.SecurityImpact.PlausibleImpact}}</p>
        <p><strong>Unverified Bounds:</strong> {{.SecurityImpact.UnverifiedImpact}}</p>
      </div>

      <div class="sub-box">
        <div class="sub-box-title">Verification Evaluation Outcome [{{.Verification.MethodOrPolicy}}]</div>
        <p style="font-size: 0.9rem;">{{.Verification.ResultSummary}}</p>
        {{if .Verification.CriteriaNotSatisfied}}
        <div style="font-size: 0.85rem; color: #fde047; margin-top: 0.4rem;">
          <strong>Unsatisfied Criteria:</strong> {{range $i, $c := .Verification.CriteriaNotSatisfied}}{{if $i}}, {{end}}{{$c}}{{end}}
        </div>
        {{end}}
      </div>

      <div class="sub-box">
        <div class="sub-box-title">Evidence Excerpt</div>
        <p style="font-size: 0.9rem;">{{.Evidence.Observation}}</p>
        {{if .Evidence.HTTPStatus}}
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
          HTTP Response Status: <strong>{{.Evidence.HTTPStatus}}</strong>
        </p>
        {{end}}
      </div>
      {{if .Evidence.NegativeEvidence}}
      <div class="sub-box negative-evidence-box">
        <div class="sub-box-title">Negative Evidence / Safety Verification</div>
        <p style="font-size: 0.9rem;">{{.Evidence.NegativeEvidence}}</p>
      </div>
      {{end}}
    </div>
    {{end}}
    {{end}}
  </section>

  <!-- 7. Observations -->
  <section id="section-observations">
    <h2>7. Observations ({{len .Observations}})</h2>
    <div class="notice-box">
      Observations reflect informational technical characteristics, client configuration baselines, or asset inventory discoveries that do not constitute security vulnerabilities.
    </div>

    {{if eq (len .Observations) 0}}
    <p style="color: var(--text-muted); font-style: italic;">No general observations recorded.</p>
    {{else}}
    {{range .Observations}}
    <div class="item-card">
      <div class="item-header">
        <div class="item-title">[{{.ObservationID}}] {{.Title}}</div>
        <div>
          <span class="badge badge-OBSERVED">{{.ObservationType}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
        </div>
      </div>
      <div class="item-meta">
        <span><strong>Asset:</strong> <code>{{.AffectedAsset}}</code></span>
        <span><strong>Source:</strong> {{.ObservationSource}}</span>
        <span><strong>Context:</strong> {{.AssessmentContext}}</span>
      </div>
      <p style="font-size: 0.92rem; margin-bottom: 0.75rem;">{{.Description}}</p>
      {{if .Evidence}}
      <div class="sub-box">
        <div class="sub-box-title">Observed Evidence</div>
        <p style="font-size: 0.88rem;">{{.Evidence}}</p>
      </div>
      {{end}}
    </div>
    {{end}}
    {{end}}
  </section>

  <!-- 8. Technical Appendix -->
  <section id="section-appendix">
    <h2>8. Technical Appendix</h2>

    <h3>Defensive & Negative Verification Outcomes</h3>
    <div class="notice-box negative-evidence-box">
      Negative verification establishes that tested defensive controls or authentication boundaries were enforced under evaluated conditions. Affirmative non-exposures do not constitute security findings.
    </div>
    {{if eq (len .TechnicalAppendix.NegativeVerificationOutcomes) 0}}
    <p style="color: var(--text-muted); font-style: italic; margin-bottom: 1.5rem;">No negative verification probes recorded.</p>
    {{else}}
    <table class="data-table">
      <thead>
        <tr>
          <th>Finding ID</th>
          <th>Policy</th>
          <th>Target / Endpoint</th>
          <th>Tested Outcome</th>
          <th>Limitations</th>
        </tr>
      </thead>
      <tbody>
        {{range .TechnicalAppendix.NegativeVerificationOutcomes}}
        <tr>
          <td><code>{{.FindingID}}</code></td>
          <td>{{.PolicyID}}</td>
          <td><code>{{.Endpoint}}</code></td>
          <td>{{.ResultSummary}}</td>
          <td style="font-size: 0.82rem; color: var(--text-secondary);">
            {{range .Limitations}}{{.}} {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{end}}

    <h3>Complete Finding Traceability Index</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Source</th>
          <th>Category</th>
          <th>Policy / Rule</th>
          <th>Severity</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {{range .TechnicalAppendix.FindingIndex}}
        <tr>
          <td><code>{{.FindingID}}</code></td>
          <td>{{.Title}}</td>
          <td>{{.SourceEngine}}</td>
          <td>{{.Category}}</td>
          <td>{{.PolicyOrRuleID}}</td>
          <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
          <td><span class="badge badge-{{.CanonicalStatus}}">{{.CanonicalStatus}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>

    <h3>Engine Execution Metrics</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>Engine</th>
          <th>Version</th>
          <th>Status</th>
          <th>Analyzed Items</th>
          <th>Output Findings</th>
        </tr>
      </thead>
      <tbody>
        {{range .TechnicalAppendix.EngineExecutionSummary}}
        <tr>
          <td><code>{{.EngineName}}</code></td>
          <td>{{.Version}}</td>
          <td>{{.Status}}</td>
          <td>{{.AssetsAnalyzed}}</td>
          <td>{{.FindingsCount}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>

    <h3>Correlation Rules Catalog</h3>
    <ul style="padding-left: 1.25rem; font-size: 0.88rem; line-height: 1.7; color: var(--text-secondary);">
      {{range .TechnicalAppendix.CorrelationRulesEvaluated}}
      <li>{{.}}</li>
      {{end}}
    </ul>
  </section>

  <!-- Footer -->
  <footer>
    <p>Generated by <strong>Felix Security Auditor</strong> &bull; Commercial Report 2.0 Specification &bull; Confidential Assessment Document</p>
    <p style="margin-top: 0.25rem; font-size: 0.78rem;">Note: Remediation recommendations are excluded from Stage 12 and reserved for Remediation Intelligence 3.0.</p>
  </footer>

</div>
</body>
</html>`

// GenerateCommercialHTML renders a CommercialReport struct into an offline HTML document.
func GenerateCommercialHTML(cr CommercialReport) (string, error) {
	tmpl, err := template.New("felix-commercial-report").Parse(commercialHTMLReportTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cr); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WriteCommercialHTML writes the self-contained CommercialReport HTML document to disk.
func WriteCommercialHTML(cr CommercialReport, filePath string) error {
	content, err := GenerateCommercialHTML(cr)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(content), 0644)
}
