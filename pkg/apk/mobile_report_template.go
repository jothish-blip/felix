package apk

const mobileAuditHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}} — {{.APKFileName}}</title>
<style>
  :root {
    --bg-base: #08090c;
    --bg-surface: #101217;
    --bg-surface-elevated: #171a22;
    --bg-surface-subtle: #1e222d;
    --border-subtle: #242938;
    --border-default: #2e3547;
    --border-strong: #3f475e;
    --text-primary: #f3f4f6;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;

    --crit: #ef4444;
    --crit-bg: #2d1215;
    --crit-border: #7f1d1d;
    --high: #f97316;
    --high-bg: #2d180e;
    --high-border: #7c2d12;
    --med: #f59e0b;
    --med-bg: #2d2208;
    --med-border: #78350f;
    --low: #3b82f6;
    --low-bg: #0e1f3d;
    --low-border: #1d4ed8;
    --info: #94a3b8;
    --info-bg: #1a202c;
    --info-border: #334155;

    --success: #10b981;
    --success-bg: #06281e;
    --success-border: #047857;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-base);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2.5rem 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 1280px; margin: 0 auto; }

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
  .brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }
  .brand-badge {
    background: #4f46e5;
    color: #fff;
    font-size: 0.75rem;
    font-weight: 800;
    letter-spacing: 0.1em;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    text-transform: uppercase;
  }
  .brand-sub {
    font-size: 0.85rem;
    color: var(--text-muted);
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  h1 {
    font-size: 2rem;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: -0.02em;
    line-height: 1.2;
  }
  .header-meta {
    margin-top: 0.75rem;
    display: flex;
    flex-wrap: wrap;
    gap: 1.25rem;
    color: var(--text-secondary);
    font-size: 0.9rem;
  }
  .header-meta span strong { color: var(--text-primary); }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.85rem;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .status-pill.completed { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
  .status-pill.static-only { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }
  .status-pill.partial { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .status-pill.failed { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }

  /* Metrics Grid */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }
  .metric-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.5rem;
    padding: 1.25rem;
    text-align: center;
  }
  .metric-value {
    font-size: 2.25rem;
    font-weight: 800;
    line-height: 1.1;
    margin-bottom: 0.25rem;
  }
  .metric-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.05em;
  }

  .metric-card.crit .metric-value { color: var(--crit); }
  .metric-card.high .metric-value { color: var(--high); }
  .metric-card.med .metric-value { color: var(--med); }
  .metric-card.low .metric-value { color: var(--low); }
  .metric-card.info .metric-value { color: var(--info); }
  .metric-card.neutral .metric-value { color: var(--text-primary); }

  /* Section Styling */
  section {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 0.75rem;
    padding: 2rem;
    margin-bottom: 2rem;
  }
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 1rem;
    margin-bottom: 1.5rem;
  }
  h2 {
    font-size: 1.35rem;
    font-weight: 700;
    color: #ffffff;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .section-badge {
    font-size: 0.75rem;
    padding: 0.2rem 0.6rem;
    border-radius: 9999px;
    background: var(--bg-surface-subtle);
    color: var(--text-secondary);
    border: 1px solid var(--border-default);
    font-weight: 600;
  }

  /* Executive Summary Banner */
  .exec-summary {
    background: var(--bg-surface-elevated);
    border-left: 4px solid #6366f1;
    padding: 1.25rem 1.5rem;
    border-radius: 0 0.5rem 0.5rem 0;
    margin-bottom: 1.5rem;
    color: var(--text-primary);
    font-size: 0.95rem;
  }

  /* Key-Value Metadata Grid */
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
  }
  .meta-item {
    background: var(--bg-surface-elevated);
    padding: 0.85rem 1rem;
    border-radius: 0.5rem;
    border: 1px solid var(--border-subtle);
  }
  .meta-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
  }
  .meta-val {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text-primary);
    word-break: break-all;
    font-family: SFMono-Regular, Consolas, monospace;
  }

  /* Tables */
  .table-wrapper {
    overflow-x: auto;
    margin-top: 1rem;
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    text-align: left;
  }
  th {
    background: var(--bg-surface-elevated);
    color: var(--text-secondary);
    padding: 0.85rem 1rem;
    font-weight: 700;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border-default);
  }
  td {
    padding: 0.85rem 1rem;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    vertical-align: top;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255, 255, 255, 0.02); }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .badge.critical { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }
  .badge.high { background: var(--high-bg); color: var(--high); border: 1px solid var(--high-border); }
  .badge.medium { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge.low { background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }
  .badge.info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

  .badge.tested { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
  .badge.skipped { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }
  .badge.failed { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }
  .badge.inconclusive { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }

  .badge.confirmed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
  .badge.inferred { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
  .badge.unresolved { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); }

  .badge.p1 { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }
  .badge.p2 { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge.p3 { background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }

  /* Filter and Search Controls */
  .filter-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: center;
    margin-bottom: 1.25rem;
  }
  .search-input {
    flex: 1;
    min-width: 240px;
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-primary);
    padding: 0.5rem 0.85rem;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    outline: none;
  }
  .search-input:focus { border-color: #6366f1; }
  .filter-btn {
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    padding: 0.45rem 0.8rem;
    border-radius: 0.375rem;
    font-size: 0.8rem;
    cursor: pointer;
    font-weight: 600;
  }
  .filter-btn:hover, .filter-btn.active {
    background: #4f46e5;
    color: #fff;
    border-color: #4f46e5;
  }

  /* Finding Item Card */
  .finding-card {
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
  }
  .finding-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #fff;
  }
  .finding-id {
    font-family: SFMono-Regular, Consolas, monospace;
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .finding-meta {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
  }
  .finding-desc {
    font-size: 0.9rem;
    color: var(--text-primary);
    margin-bottom: 0.75rem;
  }
  details {
    margin-top: 0.5rem;
    border: 1px solid var(--border-subtle);
    border-radius: 0.375rem;
    padding: 0.5rem 0.75rem;
    background: var(--bg-surface-subtle);
  }
  summary {
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--text-secondary);
    user-select: none;
    outline: none;
  }
  summary:hover { color: var(--text-primary); }
  pre {
    margin-top: 0.5rem;
    background: #000;
    padding: 0.75rem;
    border-radius: 0.25rem;
    overflow-x: auto;
    font-family: SFMono-Regular, Consolas, monospace;
    font-size: 0.8rem;
    color: #a7f3d0;
  }
  code { font-family: SFMono-Regular, Consolas, monospace; }

  /* Empty State */
  .empty-state {
    text-align: center;
    padding: 2.5rem 1rem;
    color: var(--text-muted);
    font-size: 0.95rem;
    border: 1px dashed var(--border-default);
    border-radius: 0.5rem;
  }

  /* Scope Stage Items */
  .scope-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .scope-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    padding: 0.75rem 1rem;
    border-radius: 0.375rem;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .scope-name {
    font-weight: 600;
    font-size: 0.9rem;
  }
  .scope-details {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }

  /* Remediation Card */
  .remediation-card {
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 0.5rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .remediation-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  /* Print Stylesheet */
  @media print {
    body { background: #fff !important; color: #000 !important; padding: 0 !important; font-size: 10pt; }
    .container { max-width: 100% !important; margin: 0 !important; }
    header, section, .finding-card, .remediation-card { border-color: #ddd !important; background: #fff !important; color: #000 !important; page-break-inside: avoid; }
    .filter-bar, .search-input, .filter-btn { display: none !important; }
    h1, h2, .finding-title { color: #000 !important; }
    td, th { color: #000 !important; border-color: #ccc !important; }
    pre { background: #f4f4f4 !important; color: #000 !important; border: 1px solid #ccc; }
    .badge { border: 1px solid #000 !important; color: #000 !important; background: transparent !important; }
  }

  /* Responsive Mobile Tweaks */
  @media (max-width: 768px) {
    body { padding: 1rem 0.75rem; }
    header { flex-direction: column; }
    .meta-grid { grid-template-columns: 1fr; }
    .metrics-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="container">

  <!-- A. Report Overview & Header -->
  <header>
    <div>
      <div class="brand">
        <span class="brand-badge">FELIX</span>
        <span class="brand-sub">Mobile Application Security Audit</span>
      </div>
      <h1>{{.Title}}</h1>
      <div class="header-meta">
        <span>Target: <strong>{{.APKFileName}}</strong></span>
        <span>Generated: <strong>{{.GeneratedAt}}</strong></span>
        <span>Version: <strong>{{.ReportVersion}}</strong></span>
      </div>
    </div>
    <div style="text-align: right;">
      {{if eq .Status "COMPLETED"}}
        <span class="status-pill completed">&#10003; Assessment Completed</span>
      {{else if eq .Status "STATIC_ONLY"}}
        <span class="status-pill static-only">&#9679; Static-Only Analysis</span>
      {{else if eq .Status "PARTIAL"}}
        <span class="status-pill partial">&#9888; Partial Assessment</span>
      {{else}}
        <span class="status-pill failed">&#10007; Assessment Failed</span>
      {{end}}
      <div style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-muted);">
        Mode: {{.AnalysisMode}}
      </div>
    </div>
  </header>

  <!-- Executive Summary -->
  <div class="exec-summary">
    <strong>Executive Summary:</strong> {{.ExecutiveSummary}}
  </div>

  <!-- Summary Metrics Cards -->
  <div class="metrics-grid">
    <div class="metric-card crit">
      <div class="metric-value">{{.CriticalCount}}</div>
      <div class="metric-label">Critical Findings</div>
    </div>
    <div class="metric-card high">
      <div class="metric-value">{{.HighCount}}</div>
      <div class="metric-label">High Findings</div>
    </div>
    <div class="metric-card med">
      <div class="metric-value">{{.MediumCount}}</div>
      <div class="metric-label">Medium Findings</div>
    </div>
    <div class="metric-card low">
      <div class="metric-value">{{.LowCount}}</div>
      <div class="metric-label">Low Findings</div>
    </div>
    <div class="metric-card info">
      <div class="metric-value">{{.InfoCount}}</div>
      <div class="metric-label">Informational</div>
    </div>
    <div class="metric-card neutral">
      <div class="metric-value">{{.TotalEndpoints}}</div>
      <div class="metric-label">Backend Endpoints</div>
    </div>
    <div class="metric-card neutral">
      <div class="metric-value">{{.TotalServices}}</div>
      <div class="metric-label">Service Indicators</div>
    </div>
  </div>

  <!-- B. APK Metadata -->
  <section id="metadata">
    <div class="section-header">
      <h2>&#128241; APK Package Metadata</h2>
      <span class="section-badge">Intake & Verification</span>
    </div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Package Name</div>
        <div class="meta-val">{{.PackageName}}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Version Name / Code</div>
        <div class="meta-val">{{.VersionName}} ({{.VersionCode}})</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Target SDK / Min SDK</div>
        <div class="meta-val">Target: {{.TargetSDK}} | Min: {{.MinSDK}}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">APK SHA-256</div>
        <div class="meta-val" title="{{.APKSHA256}}">{{.APKSHA256}}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Package File Size</div>
        <div class="meta-val">{{.APKFileSizeFormatted}}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Archive Entries / Uncompressed</div>
        <div class="meta-val">{{.ArchiveEntryCount}} entries ({{.TotalDecompressedSize}})</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Manifest Format & Status</div>
        <div class="meta-val">{{.ManifestFormat}} — {{.ManifestStatus}}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Bytecode & Multidex</div>
        <div class="meta-val">{{.Multidex}}</div>
      </div>
    </div>
  </section>

  <!-- C. Security Findings -->
  <section id="findings">
    <div class="section-header">
      <h2>&#9888; Security Findings</h2>
      <span class="section-badge">{{.TotalFindings}} Finding(s) Identified</span>
    </div>

    <!-- Search and Severity Filter Bar -->
    <div class="filter-bar">
      <input type="text" id="findingSearch" class="search-input" placeholder="Search findings by title, ID, component, or description...">
      <button class="filter-btn active" data-filter="all">All ({{.TotalFindings}})</button>
      <button class="filter-btn" data-filter="critical">Critical ({{.CriticalCount}})</button>
      <button class="filter-btn" data-filter="high">High ({{.HighCount}})</button>
      <button class="filter-btn" data-filter="medium">Medium ({{.MediumCount}})</button>
      <button class="filter-btn" data-filter="low">Low ({{.LowCount}})</button>
      <button class="filter-btn" data-filter="info">Info ({{.InfoCount}})</button>
    </div>

    {{if eq .TotalFindings 0}}
      <div class="empty-state">
        &#10003; No security exposures or non-standard configurations identified in analyzed components.
      </div>
    {{else}}
      <div id="findingsList">
        {{range .Findings}}
          <div class="finding-card" data-severity="{{.SeverityClass}}" data-text="{{.Title}} {{.ID}} {{.AffectedTarget}} {{.Description}}">
            <div class="finding-header">
              <div>
                <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
                <span class="finding-id" style="margin-left: 0.5rem;">{{.ID}}</span>
                <div class="finding-title" style="margin-top: 0.25rem;">{{.Title}}</div>
              </div>
              <div style="text-align: right; font-size: 0.8rem; color: var(--text-muted);">
                Confidence: <strong style="color: var(--text-secondary);">{{.Confidence}}</strong> | Status: <strong style="color: var(--text-secondary);">{{.Status}}</strong>
              </div>
            </div>
            <div class="finding-meta">
              <strong>Component / Target:</strong> <code>{{.AffectedTarget}}</code> |
              <strong>Source:</strong> {{.Source}}
            </div>
            <div class="finding-desc">
              {{.Description}}
            </div>
            {{if .Evidence}}
              <details>
                <summary>&#128065; Technical Evidence & Observation</summary>
                <pre><code>{{.Evidence}}</code></pre>
              </details>
            {{end}}
            {{if .Remediation}}
              <div style="margin-top: 0.75rem; font-size: 0.85rem; color: #a7f3d0; background: rgba(16, 185, 129, 0.08); padding: 0.6rem 0.85rem; border-radius: 0.375rem; border: 1px solid rgba(16, 185, 129, 0.2);">
                <strong>Remediation:</strong> {{.Remediation}}
              </div>
            {{end}}
          </div>
        {{end}}
      </div>
    {{end}}
  </section>

  <!-- D. Service Indicators -->
  <section id="services">
    <div class="section-header">
      <h2>&#9729; Embedded Service & Infrastructure Indicators</h2>
      <span class="section-badge">{{.TotalServices}} Indicator(s)</span>
    </div>
    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
      Discovered third-party cloud SDKs, storage buckets, database URIs, and external services. The presence of a service indicator reflects integration architecture and does not prove exploitability without verification.
    </p>

    {{if eq .TotalServices 0}}
      <div class="empty-state">
        No external database, cloud storage, or infrastructure indicators discovered in artifacts.
      </div>
    {{else}}
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Provider / Service</th>
              <th>Category</th>
              <th>Host / Identifier</th>
              <th>Source Origin</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {{range .ServiceIndicators}}
              <tr>
                <td><strong>{{.Provider}}</strong></td>
                <td>{{.Category}}</td>
                <td><code>{{.HostIdentifier}}</code></td>
                <td><code>{{.SourceArtifact}}</code></td>
                <td><span class="badge info">{{.Confidence}}</span></td>
              </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    {{end}}
  </section>

  <!-- E. Backend Inventory -->
  <section id="inventory">
    <div class="section-header">
      <h2>&#128279; Backend Endpoint & Host Inventory</h2>
      <span class="section-badge">{{.TotalEndpoints}} Endpoint(s) across {{.TotalHosts}} Host(s)</span>
    </div>

    {{if eq .TotalEndpoints 0}}
      <div class="empty-state">
        No backend API hosts, routes, or storage endpoints were discovered in analyzed artifacts.
      </div>
    {{else}}
      <!-- Inventory Summary Sub-Cards -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem;">
        <div class="meta-item">
          <div class="meta-label">Confirmed References</div>
          <div class="meta-val" style="color: var(--success);">{{.ConfirmedCount}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Inferred Routes</div>
          <div class="meta-val" style="color: var(--med);">{{.InferredCount}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Unresolved Routes</div>
          <div class="meta-val" style="color: var(--text-muted);">{{.UnresolvedCount}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Backend Hosts</div>
          <div class="meta-val">{{.TotalHosts}}</div>
        </div>
      </div>

      <!-- Backend Hosts Table -->
      <h3 style="font-size: 1.05rem; margin-bottom: 0.75rem; color: #fff;">Discovered Backend Hosts</h3>
      <div class="table-wrapper" style="margin-bottom: 2rem;">
        <table>
          <thead>
            <tr>
              <th>Host Identity</th>
              <th>Endpoints</th>
              <th>Confirmed / Inferred</th>
              <th>Service Indicators</th>
              <th>Origin Artifacts</th>
            </tr>
          </thead>
          <tbody>
            {{range .Hosts}}
              <tr>
                <td><code>{{.HostIdentity}}</code></td>
                <td><strong>{{.EndpointCount}}</strong></td>
                <td>{{.ConfirmedCount}} confirmed, {{.InferredCount}} inferred</td>
                <td>
                  {{if .ServiceIndicators}}
                    {{range .ServiceIndicators}}<span class="badge info" style="margin-right: 0.25rem;">{{.}}</span>{{end}}
                  {{else}}
                    <span style="color: var(--text-muted); font-size: 0.8rem;">General Backend</span>
                  {{end}}
                </td>
                <td>
                  {{range .ArtifactOrigins}}<code style="font-size: 0.75rem; margin-right: 0.35rem;">{{.}}</code>{{end}}
                </td>
              </tr>
            {{end}}
          </tbody>
        </table>
      </div>

      <!-- Endpoints Table with Filter -->
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
        <h3 style="font-size: 1.05rem; color: #fff;">Normalized Endpoint Catalog</h3>
        <input type="text" id="endpointSearch" class="search-input" style="max-width: 320px;" placeholder="Filter endpoints by URL or path...">
      </div>

      <div class="table-wrapper">
        <table id="endpointsTable">
          <thead>
            <tr>
              <th>Classification</th>
              <th>Category</th>
              <th>Normalized Endpoint URL</th>
              <th>Artifact Provenance</th>
              <th>Testing Status</th>
            </tr>
          </thead>
          <tbody>
            {{range .Endpoints}}
              <tr data-url="{{.NormalizedURL}}">
                <td><span class="badge {{.ClassificationBadge}}">{{.Classification}}</span></td>
                <td><span class="badge info">{{.Category}}</span></td>
                <td><code style="word-break: break-all;">{{.NormalizedURL}}</code></td>
                <td><code>{{.ProvenanceArtifact}}</code></td>
                <td>
                  {{if eq .TestedStatus "Actively Audited"}}
                    <span class="badge tested">&#10003; Audited</span>
                  {{else}}
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Untested (Static Only)</span>
                  {{end}}
                </td>
              </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    {{end}}
  </section>

  <!-- F. Authorized Assessment Results -->
  <section id="assessment">
    <div class="section-header">
      <h2>&#128737; Authorized Backend Assessment Results</h2>
      <span class="section-badge">{{.AssessmentStatus}}</span>
    </div>

    {{if not .AssessmentExecuted}}
      <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-default); border-left: 4px solid var(--info); border-radius: 0.375rem; padding: 1.25rem 1.5rem;">
        <h4 style="color: #fff; margin-bottom: 0.35rem;">Active Backend Assessment Not Executed</h4>
        <p style="font-size: 0.9rem; color: var(--text-secondary); line-height: 1.5;">
          This audit was conducted in <strong>offline static-only mode</strong>. Zero network requests were transmitted to discovered backend hosts or third-party endpoints. To conduct authorized active testing against in-scope backends, execute FELIX with explicit scope certification:
          <br><br>
          <code>felix apk --analyze --assess --target &lt;authorized-url&gt; --auth-confirm &lt;path-to-apk&gt;</code>
        </p>
      </div>
    {{else}}
      <!-- Active Assessment Results Details -->
      <div class="meta-grid" style="margin-bottom: 1.5rem;">
        <div class="meta-item">
          <div class="meta-label">Scope Mode & Policy</div>
          <div class="meta-val">{{.AssessmentScopeMode}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Authorized Scope Targets</div>
          <div class="meta-val">{{range .AuthorizedTargets}}<code>{{.}}</code> {{end}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Requests Sent / Budget</div>
          <div class="meta-val">{{.AssessmentTotalRequests}} sent {{if .AssessmentBudgetExhausted}}(Budget Reached){{else}}(Within Budget){{end}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Tested / Skipped / Failed</div>
          <div class="meta-val">{{.AssessmentTotalTested}} tested / {{.AssessmentTotalSkipped}} skipped / {{.AssessmentTotalFailed}} failed / {{.AssessmentTotalInconcl}} inconv.</div>
        </div>
      </div>

      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Disposition</th>
              <th>Endpoint URL</th>
              <th>Outcome / Reason</th>
              <th>HTTP Status</th>
              <th>Dispatched</th>
              <th>Requests</th>
            </tr>
          </thead>
          <tbody>
            {{range .AssessmentResults}}
              <tr>
                <td><span class="badge {{.DispositionBadge}}">{{.Disposition}}</span></td>
                <td><code style="word-break: break-all;">{{.NormalizedURL}}</code></td>
                <td>
                  <span style="font-weight: 600; font-size: 0.8rem; color: var(--text-secondary);">{{.ReasonCode}}</span>
                  {{if .ReasonMessage}}<br><span style="font-size: 0.75rem; color: var(--text-muted);">{{.ReasonMessage}}</span>{{end}}
                </td>
                <td>
                  {{if gt .HTTPStatus 0}}
                    <code>HTTP {{.HTTPStatus}}</code> ({{.DurationMs}}ms)
                  {{else}}
                    <span style="color: var(--text-muted); font-size: 0.8rem;">N/A</span>
                  {{end}}
                </td>
                <td>{{if .RequestDispatched}}Yes{{else}}No{{end}}</td>
                <td>{{.RequestCount}}</td>
              </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    {{end}}
  </section>

  <!-- G. Remediation Guidance -->
  <section id="remediation">
    <div class="section-header">
      <h2>&#128295; Actionable Remediation Guidance</h2>
      <span class="section-badge">{{len .Remediations}} Recommendation(s)</span>
    </div>

    {{if eq (len .Remediations) 0}}
      <div class="empty-state">
        &#10003; No actionable vulnerabilities requiring immediate remediation were identified.
      </div>
    {{else}}
      {{range .Remediations}}
        <div class="remediation-card">
          <div class="remediation-header">
            <div>
              <span class="badge {{.PriorityBadge}}">{{.Priority}}</span>
              <strong style="margin-left: 0.5rem; font-size: 1rem; color: #fff;">{{.FindingTitle}}</strong>
            </div>
            <span style="font-family: SFMono-Regular, Consolas, monospace; font-size: 0.75rem; color: var(--text-muted);">{{.FindingID}}</span>
          </div>
          <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
            <strong>Target:</strong> <code>{{.AffectedComponent}}</code>
          </div>
          <div style="font-size: 0.9rem; color: var(--text-primary); margin-bottom: 0.5rem;">
            <strong>Recommended Implementation:</strong><br>
            {{.Recommendation}}
          </div>
          <div style="font-size: 0.85rem; color: #93c5fd; background: rgba(59, 130, 246, 0.08); padding: 0.5rem 0.75rem; border-radius: 0.375rem; border: 1px solid rgba(59, 130, 246, 0.2); margin-bottom: 0.5rem;">
            <strong>Verification Step:</strong> {{.VerificationStep}}
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">
            <em>Residual Caveat:</em> {{.ResidualCaveat}}
          </div>
        </div>
      {{end}}
    {{end}}
  </section>

  <!-- H. Scope and Limitations -->
  <section id="scope">
    <div class="section-header">
      <h2>&#128065; Analysis Scope, Methodology & Limitations</h2>
      <span class="section-badge">Methodology & Assurance</span>
    </div>

    <h3 style="font-size: 1rem; color: #fff; margin-bottom: 0.75rem;">Pipeline Execution Stages</h3>
    <div class="scope-list" style="margin-bottom: 1.5rem;">
      {{range .ScopeStages}}
        <div class="scope-item">
          <div>
            <div class="scope-name">{{.Name}}</div>
            <div class="scope-details">{{.Details}}</div>
          </div>
          <span class="badge {{.Badge}}">{{.Status}}</span>
        </div>
      {{end}}
    </div>

    <h3 style="font-size: 1rem; color: #fff; margin-bottom: 0.75rem;">Technical Limitations & Caveats</h3>
    <ul style="padding-left: 1.25rem; font-size: 0.875rem; color: var(--text-secondary); line-height: 1.7;">
      {{range .Limitations}}
        <li>{{.}}</li>
      {{end}}
    </ul>
  </section>

  <!-- Footer -->
  <footer style="text-align: center; font-size: 0.8rem; color: var(--text-muted); margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border-subtle);">
    Generated by <strong>FELIX</strong> :: Defensive Application & Infrastructure Security Auditor<br>
    Zero remote network dependencies required to render this document. Confidential Security Audit Artifact.
  </footer>

</div>

<!-- Client-side Interactive Filter Script (Self-Contained Vanilla JS) -->
<script>
(function() {
  // Findings search and filter
  var searchInput = document.getElementById('findingSearch');
  var filterButtons = document.querySelectorAll('.filter-btn');
  var findingCards = document.querySelectorAll('.finding-card');
  var activeSeverity = 'all';

  function applyFindingFilters() {
    var query = (searchInput ? searchInput.value : '').toLowerCase().trim();
    findingCards.forEach(function(card) {
      var cardSev = card.getAttribute('data-severity');
      var cardText = (card.getAttribute('data-text') || '').toLowerCase();
      var matchesSev = (activeSeverity === 'all' || cardSev === activeSeverity);
      var matchesText = (query === '' || cardText.indexOf(query) !== -1);
      if (matchesSev && matchesText) {
        card.style.display = '';
      } else {
        card.style.display = 'none';
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', applyFindingFilters);
  }

  filterButtons.forEach(function(btn) {
    btn.addEventListener('click', function() {
      filterButtons.forEach(function(b) { b.classList.remove('active'); });
      this.classList.add('active');
      activeSeverity = this.getAttribute('data-filter');
      applyFindingFilters();
    });
  });

  // Endpoints search filter
  var endpointSearch = document.getElementById('endpointSearch');
  var endpointRows = document.querySelectorAll('#endpointsTable tbody tr');

  if (endpointSearch) {
    endpointSearch.addEventListener('input', function() {
      var q = this.value.toLowerCase().trim();
      endpointRows.forEach(function(row) {
        var url = (row.getAttribute('data-url') || '').toLowerCase();
        if (q === '' || url.indexOf(q) !== -1) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });
  }
})();
</script>
</body>
</html>`
