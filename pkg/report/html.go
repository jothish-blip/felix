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
<title>Felix Security Audit Report — {{.Target}}</title>
<style>
  :root {
    --bg-main: #0f172a;
    --bg-card: #1e293b;
    --bg-card-sub: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --border-color: #334155;
    --crit: #ef4444;
    --high: #f97316;
    --med: #f59e0b;
    --low: #3b82f6;
    --info: #64748b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 2rem 1.5rem;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  header {
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }
  .header-title h1 { font-size: 1.75rem; font-weight: 700; color: #38bdf8; letter-spacing: -0.025em; }
  .header-title p { color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }
  .score-badge {
    background-color: var(--bg-card);
    border: 2px solid var(--border-color);
    border-radius: 0.75rem;
    padding: 0.75rem 1.25rem;
    text-align: center;
  }
  .score-val { font-size: 2rem; font-weight: 800; line-height: 1; }
  .score-lbl { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-top: 0.25rem; }

  /* Severity text colors */
  .color-CRITICAL { color: var(--crit); }
  .color-HIGH { color: var(--high); }
  .color-MEDIUM { color: var(--med); }
  .color-LOW { color: var(--low); }
  .color-INFORMATIONAL, .color-INFO { color: var(--info); }

  /* Grid & Cards */
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 0.5rem;
    padding: 1.25rem;
  }
  .card-val { font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }
  .card-lbl { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; }

  section { margin-bottom: 2.5rem; }
  h2 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border-color);
    color: #e2e8f0;
  }

  /* Badge */
  .badge {
    display: inline-block;
    padding: 0.2rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-CRITICAL { background: #450a0a; color: #fca5a5; border: 1px solid #991b1b; }
  .badge-HIGH { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
  .badge-MEDIUM { background: #451a03; color: #fde047; border: 1px solid #a16207; }
  .badge-LOW { background: #172554; color: #93c5fd; border: 1px solid #1e40af; }
  .badge-INFO { background: #1e293b; color: #cbd5e1; border: 1px solid #475569; }

  /* Tables & Lists */
  .finding-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 0.5rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .finding-title { font-weight: 600; font-size: 1.05rem; }
  .finding-meta {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
    word-break: break-all;
  }
  .finding-desc { margin-bottom: 0.75rem; font-size: 0.95rem; }
  .code-block {
    background-color: #0b1120;
    border: 1px solid #1e293b;
    border-radius: 0.25rem;
    padding: 0.75rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
    color: #e2e8f0;
    white-space: pre-wrap;
    word-break: break-all;
    margin-bottom: 0.75rem;
  }
  .remediation-box {
    background-color: #172554;
    border-left: 4px solid #3b82f6;
    padding: 0.75rem 1rem;
    border-radius: 0 0.25rem 0.25rem 0;
    font-size: 0.9rem;
    color: #bfdbfe;
  }
  .story-card {
    background-color: #1a2234;
    border-left: 4px solid #38bdf8;
    border-radius: 0.375rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .story-title { font-size: 1.1rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem; }
  .story-list { padding-left: 1.25rem; font-size: 0.9rem; color: #cbd5e1; margin-bottom: 0.75rem; }
  footer {
    text-align: center;
    font-size: 0.8rem;
    color: var(--text-secondary);
    border-top: 1px solid var(--border-color);
    padding-top: 1.5rem;
    margin-top: 3rem;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-title">
      <h1>FELIX SECURITY AUDIT REPORT</h1>
      <p>Target: <strong>{{.Target}}</strong> &bull; Generated: {{.Timestamp}}</p>
    </div>
    <div class="score-badge">
      <div class="score-val color-{{.RiskLevel}}">{{.RiskScore}}</div>
      <div class="score-lbl">Felix Risk Score ({{.RiskLevel}})</div>
    </div>
  </header>

  <section>
    <h2>Executive Summary</h2>
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
  </section>

  {{if .SecurityStories}}
  <section>
    <h2>Correlated Security Stories</h2>
    {{range .SecurityStories}}
    <div class="story-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
        <div class="story-title">{{.Title}}</div>
        <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
      </div>
      <p style="margin-bottom:0.75rem; font-size:0.95rem;">{{.Description}}</p>
      <div style="font-size:0.85rem; font-weight:600; color:#94a3b8; margin-bottom:0.25rem;">Correlated Evidence:</div>
      <ul class="story-list">
        {{range .Evidence}}
        <li>{{.}}</li>
        {{end}}
      </ul>
      <div style="font-size:0.85rem; font-weight:600; color:#fca5a5; margin-bottom:0.25rem;">Security Impact:</div>
      <p style="font-size:0.9rem; margin-bottom:0.75rem; color:#fecaca;">{{.Impact}}</p>
      <div class="remediation-box">
        <strong>Remediation:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </section>
  {{end}}

  {{if .TopPriorities}}
  <section>
    <h2>Top Actionable Priorities</h2>
    {{range .TopPriorities}}
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">{{.Title}}</div>
        <div>
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
        </div>
      </div>
      <div class="finding-meta">
        <strong>Endpoint:</strong> {{.Endpoint}} ({{.Method}}) &bull; <strong>Category:</strong> {{.Category}} &bull; <strong>Source:</strong> {{.Source}}
      </div>
      <div class="finding-desc">{{.Description}}</div>
      {{if .Evidence}}
      <div class="code-block">{{.Evidence}}</div>
      {{end}}
      <div class="remediation-box">
        <strong>Remediation:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </section>
  {{end}}

  <section>
    <h2>Detailed Findings Inventory ({{len .Findings}})</h2>
    {{if not .Findings}}
    <div class="card" style="text-align:center; padding:2rem; color:var(--text-secondary);">
      No security findings or exposures detected on this target.
    </div>
    {{end}}
    {{range .Findings}}
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">[{{.ID}}] {{.Title}}</div>
        <div>
          <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          <span class="badge badge-INFO">{{.Confidence}}</span>
        </div>
      </div>
      <div class="finding-meta">
        <strong>Endpoint:</strong> {{.Endpoint}} ({{.Method}}) &bull; <strong>Category:</strong> {{.Category}} &bull; <strong>Source:</strong> {{.Source}}
      </div>
      <div class="finding-desc">{{.Description}}</div>
      {{if .Evidence}}
      <div class="code-block">{{.Evidence}}</div>
      {{end}}
      <div class="remediation-box">
        <strong>Action:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </section>

  <section>
    <h2>Engine Coverage Breakdown</h2>
    <div class="grid">
      <div class="card">
        <div class="card-lbl">felix-crawler</div>
        <div style="font-size:0.9rem; margin-top:0.5rem; color:#94a3b8;">Asset discovery, source-map extraction & parsing.</div>
      </div>
      <div class="card">
        <div class="card-lbl">felix-secrets</div>
        <div style="font-size:0.9rem; margin-top:0.5rem; color:#94a3b8;">High-entropy tokens, service keys & pattern analysis.</div>
      </div>
      <div class="card">
        <div class="card-lbl">felix-cloud</div>
        <div style="font-size:0.9rem; margin-top:0.5rem; color:#94a3b8;">Supabase, Firebase, S3, and GCS verification.</div>
      </div>
      <div class="card">
        <div class="card-lbl">felix-api</div>
        <div style="font-size:0.9rem; margin-top:0.5rem; color:#94a3b8;">GraphQL, CORS, sensitive configs (.env) & headers.</div>
      </div>
    </div>
  </section>

  <footer>
    <p>Generated by <strong>Project Felix</strong> &bull; Defensive, evidence-first web security auditing.</p>
  </footer>
</div>
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
