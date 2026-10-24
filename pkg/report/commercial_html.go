package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

const commercialHTMLReportTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Felix Commercial Security Assessment Report — {{.ExecutiveSummary.Target}}</title>
<style>
  :root, [data-theme="dark"] {
    --bg-canvas: #000000;
    --bg-surface: #080808;
    --bg-elevated: #101010;
    --bg-subtle: #141414;
    --border-subtle: #1f1f1f;
    --border-default: #292929;
    --border-strong: #3d3d3d;
    --text-primary: #f5f5f5;
    --text-secondary: #a3a3a3;
    --text-muted: #737373;
    --gauge-bg: #1c1c1c;

    --crit: #ff5a5f;
    --crit-bg: rgba(255, 90, 95, 0.10);
    --crit-border: rgba(255, 90, 95, 0.28);
    --high: #ff9f43;
    --high-bg: rgba(255, 159, 67, 0.10);
    --high-border: rgba(255, 159, 67, 0.28);
    --med: #e5c65a;
    --med-bg: rgba(229, 198, 90, 0.10);
    --med-border: rgba(229, 198, 90, 0.28);
    --low: #60a5fa;
    --low-bg: rgba(96, 165, 250, 0.10);
    --low-border: rgba(96, 165, 250, 0.28);
    --info: #888888;
    --info-bg: rgba(136, 136, 136, 0.10);
    --info-border: rgba(136, 136, 136, 0.28);

    --verified: #34d399;
    --verified-bg: rgba(52, 211, 153, 0.10);
    --verified-border: rgba(52, 211, 153, 0.28);
    --detected: #e5c65a;
    --detected-bg: rgba(229, 198, 90, 0.10);
    --detected-border: rgba(229, 198, 90, 0.28);
    --not-verified: #737373;
    --not-verified-bg: rgba(115, 115, 115, 0.10);
    --not-verified-border: rgba(115, 115, 115, 0.28);
    --not-exposed: #2dd4bf;
    --not-exposed-bg: rgba(45, 212, 191, 0.10);
    --not-exposed-border: rgba(45, 212, 191, 0.28);
  }

  [data-theme="light"] {
    --bg-canvas: #ffffff;
    --bg-surface: #fafafa;
    --bg-elevated: #f4f4f5;
    --bg-subtle: #ebebef;
    --border-subtle: #e4e4e7;
    --border-default: #d4d4d8;
    --border-strong: #a1a1aa;
    --text-primary: #09090b;
    --text-secondary: #52525b;
    --text-muted: #71717a;
    --gauge-bg: #e4e4e7;

    --crit: #dc2626;
    --crit-bg: #fee2e2;
    --crit-border: #fca5a5;
    --high: #ea580c;
    --high-bg: #ffedd5;
    --high-border: #fdba74;
    --med: #d97706;
    --med-bg: #fef3c7;
    --med-border: #fde047;
    --low: #2563eb;
    --low-bg: #dbeafe;
    --low-border: #93c5fd;
    --info: #52525b;
    --info-bg: #f4f4f5;
    --info-border: #d4d4d8;

    --verified: #059669;
    --verified-bg: #d1fae5;
    --verified-border: #6ee7b7;
    --detected: #d97706;
    --detected-bg: #fef3c7;
    --detected-border: #fde047;
    --not-verified: #71717a;
    --not-verified-bg: #f4f4f5;
    --not-verified-border: #d4d4d8;
    --not-exposed: #0d9488;
    --not-exposed-bg: #ccfbf1;
    --not-exposed-border: #5eead4;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Helvetica Neue", "Inter", Arial, sans-serif;
    background-color: var(--bg-canvas);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 2rem 1.5rem;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
    transition: background-color 0.15s ease, color 0.15s ease;
  }
  .container { max-width: 1240px; margin: 0 auto; }

  /* Top Navigation Toolbar */
  .top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 0.85rem;
    margin-bottom: 1.75rem;
    border-bottom: 1px solid var(--border-subtle);
  }
  .brand-tag {
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.625rem;
  }
  .action-btn {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    color: var(--text-primary);
    padding: 0.35rem 0.75rem;
    border-radius: 6px;
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    transition: all 0.15s ease;
  }
  .action-btn:hover {
    border-color: var(--border-strong);
    background: var(--bg-elevated);
  }
  .action-btn-pdf {
    background: var(--bg-elevated);
    border-color: var(--border-strong);
  }
  .action-icon {
    display: inline-block;
    vertical-align: middle;
    color: var(--text-secondary);
  }
  .action-btn:hover .action-icon {
    color: var(--text-primary);
  }

  header {
    border-bottom: 1px solid var(--border-default);
    padding-bottom: 1.75rem;
    margin-bottom: 2.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.5rem;
  }
  .header-title h1 {
    font-size: 1.625rem;
    font-weight: 600;
    color: var(--text-primary);
    letter-spacing: -0.025em;
    line-height: 1.25;
  }
  .header-meta {
    margin-top: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
    display: flex;
    flex-wrap: wrap;
    gap: 1.25rem;
    align-items: center;
  }
  .header-meta span strong { color: var(--text-primary); font-weight: 500; }

  /* Precision Exposure Score Card */
  .score-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    min-width: 220px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  .score-card-lbl {
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 500;
    margin-bottom: 0.35rem;
  }
  .score-card-row {
    display: flex;
    align-items: baseline;
    gap: 0.35rem;
  }
  .score-val {
    font-size: 2.125rem;
    font-weight: 600;
    line-height: 1;
    letter-spacing: -0.02em;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  .score-denom {
    font-size: 0.8125rem;
    color: var(--text-muted);
    font-weight: 500;
    margin-left: 0.15rem;
  }
  .score-verdict {
    margin-left: auto;
    font-size: 0.6875rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
  }
  .score-meter-track {
    height: 4px;
    background-color: var(--gauge-bg);
    border-radius: 2px;
    overflow: hidden;
    margin-top: 0.75rem;
  }
  .score-meter-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.4s ease;
  }

  nav.toc {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 0.95rem 1.25rem;
    margin-bottom: 2.25rem;
  }
  .toc-title { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 0.65rem; }
  .toc-links { display: flex; flex-wrap: wrap; gap: 0.5rem 0.85rem; }
  .toc-links a {
    color: var(--low);
    text-decoration: none;
    font-size: 0.8125rem;
    font-weight: 500;
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    background: var(--low-bg);
    border: 1px solid var(--low-border);
    transition: all 0.15s ease;
  }
  .toc-links a:hover { filter: brightness(1.15); }

  section { margin-bottom: 3rem; }
  h2 {
    font-size: 1.1875rem;
    font-weight: 600;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 0.65rem;
    margin-bottom: 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.65rem;
    letter-spacing: -0.02em;
  }
  h3 {
    font-size: 0.8125rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin: 1.75rem 0 0.85rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  h3::after {
    content: "";
    flex: 1;
    height: 1px;
    background: var(--border-subtle);
  }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
  .card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 0.95rem 1.15rem;
    position: relative;
    transition: border-color 0.15s ease;
  }
  .card:hover { border-color: var(--border-strong); }
  .card-lbl { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); font-weight: 500; margin-bottom: 0.35rem; }
  .card-val { font-size: 1.5rem; font-weight: 600; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; letter-spacing: -0.02em; line-height: 1.1; }
  .card.card-crit { border-top: 2px solid var(--crit); }
  .card.card-high { border-top: 2px solid var(--high); }
  .card.card-med { border-top: 2px solid var(--med); }
  .card.card-low { border-top: 2px solid var(--low); }
  .card.card-info { border-top: 2px solid var(--info); }

  .narrative-box {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-left: 3px solid var(--low);
    border-radius: 8px;
    padding: 1.1rem 1.35rem;
    margin-bottom: 1.25rem;
    font-size: 0.875rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }
  .narrative-box p { margin-bottom: 0.5rem; }
  .narrative-box p:last-child { margin-bottom: 0; }
  .narrative-box strong { color: var(--text-primary); font-weight: 600; }

  .notice-box {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 0.85rem 1.15rem;
    margin-bottom: 1.25rem;
    font-size: 0.8125rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border: 1px solid transparent;
    line-height: 1.2;
  }
  .badge-CRITICAL, .badge-CRIT { background: var(--crit-bg); color: var(--crit); border-color: var(--crit-border); }
  .badge-HIGH { background: var(--high-bg); color: var(--high); border-color: var(--high-border); }
  .badge-MEDIUM, .badge-MED { background: var(--med-bg); color: var(--med); border-color: var(--med-border); }
  .badge-LOW { background: var(--low-bg); color: var(--low); border-color: var(--low-border); }
  .badge-INFO, .badge-INFORMATIONAL { background: var(--info-bg); color: var(--info); border-color: var(--info-border); }
  .badge-VERIFIED { background: var(--verified-bg); color: var(--verified); border-color: var(--verified-border); }
  .badge-DETECTED { background: var(--detected-bg); color: var(--detected); border-color: var(--detected-border); }
  .badge-NOT_VERIFIED { background: var(--not-verified-bg); color: var(--not-verified); border-color: var(--not-verified-border); }
  .badge-EVIDENCE_SUPPORTED, .badge-OBSERVED { background: var(--bg-elevated); color: var(--text-secondary); border-color: var(--border-default); }
  .badge-NOT_EXPOSED, .badge-DEFENDED { background: var(--not-exposed-bg); color: var(--not-exposed); border-color: var(--not-exposed-border); }
  .badge-SYNTHETIC { background: rgba(168, 85, 247, 0.12); color: #c084fc; border-color: rgba(168, 85, 247, 0.3); }

  .color-CRITICAL { color: var(--crit); }
  .color-HIGH { color: var(--high); }
  .color-MEDIUM { color: var(--med); }
  .color-LOW { color: var(--low); }
  .color-INFORMATIONAL, .color-INFO { color: var(--info); }

  /* Expandable Finding Cards */
  .finding-card-details {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    margin-bottom: 0.75rem;
    overflow: hidden;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }
  .finding-card-details:hover { border-color: var(--border-default); }
  .finding-card-details[open] { border-color: var(--border-strong); }
  .finding-summary-row {
    padding: 0.85rem 1.15rem;
    cursor: pointer;
    font-weight: 500;
    font-size: 0.875rem;
    color: var(--text-primary);
    list-style: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
    gap: 0.75rem;
    flex-wrap: wrap;
    transition: background 0.15s ease;
  }
  .finding-summary-row::-webkit-details-marker { display: none; }
  .finding-header-left {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    flex-wrap: wrap;
    flex: 1;
  }
  .finding-header-right {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .chevron {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: transform 0.15s ease;
    color: var(--text-muted);
  }
  .finding-card-details[open] .finding-summary-row .chevron {
    transform: rotate(180deg);
  }
  .finding-card-details[open] .finding-summary-row {
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
  }
  .finding-body {
    padding: 1.15rem 1.25rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .item-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 1.15rem 1.25rem;
    margin-bottom: 1.25rem;
  }
  .item-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .item-title { font-size: 0.95rem; font-weight: 600; color: var(--text-primary); }
  .item-meta {
    font-size: 0.8125rem;
    color: var(--text-secondary);
    margin-bottom: 0.85rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem 1.25rem;
    background: var(--bg-elevated);
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    border: 1px solid var(--border-subtle);
  }
  .item-meta strong { color: var(--text-primary); font-weight: 500; }
  .item-desc { font-size: 0.875rem; margin-bottom: 1rem; color: var(--text-secondary); line-height: 1.6; }

  .sub-box {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    padding: 0.85rem 1.15rem;
    margin-bottom: 0.85rem;
  }
  .sub-box-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin-bottom: 0.4rem;
  }

  .impact-box {
    background: var(--crit-bg);
    border: 1px solid var(--crit-border);
    border-left: 3px solid var(--crit);
    border-radius: 6px;
    padding: 0.85rem 1.15rem;
    margin-bottom: 0.85rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
    line-height: 1.6;
  }
  .impact-title { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--crit); margin-bottom: 0.35rem; }

  /* Code Snippets & Copy Button */
  .evidence-header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.35rem;
  }
  .code-snippet {
    background: var(--bg-canvas);
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    padding: 0.65rem 0.85rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.8rem;
    color: var(--text-primary);
    overflow-x: auto;
    word-break: break-all;
    margin-top: 0.35rem;
  }
  .copy-btn {
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .copy-btn:hover {
    color: var(--text-primary);
    border-color: var(--border-strong);
  }
  .copy-btn.copied {
    color: var(--verified);
    border-color: var(--verified);
  }

  .table-wrapper {
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    overflow: hidden;
    background: var(--bg-surface);
    margin-bottom: 1.25rem;
  }
  table.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8125rem;
  }
  table.data-table th, table.data-table td {
    padding: 0.65rem 0.85rem;
    text-align: left;
    border-bottom: 1px solid var(--border-subtle);
  }
  table.data-table th {
    background: var(--bg-elevated);
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.6875rem;
    letter-spacing: 0.05em;
  }
  table.data-table tr:last-child td { border-bottom: none; }
  table.data-table tr:hover td { background: var(--bg-subtle); }

  .clean-list {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    margin-bottom: 1.5rem;
    padding: 0;
  }
  .clean-list-item {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    padding: 0.65rem 0.85rem;
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    font-size: 0.85rem;
    line-height: 1.5;
    color: var(--text-secondary);
    transition: border-color 0.15s ease;
  }
  .clean-list-item:hover { border-color: var(--border-default); }
  .clean-list-item strong { color: var(--text-primary); font-weight: 600; }
  .clean-list-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--border-strong);
    margin-top: 0.45rem;
    flex-shrink: 0;
  }
  .clean-list-item code {
    background: var(--bg-subtle);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    padding: 0.1rem 0.35rem;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.8rem;
    color: var(--text-primary);
  }

  .risk-track {
    background: var(--gauge-bg);
    border-radius: 9999px;
    height: 6px;
    overflow: hidden;
    margin: 0.5rem 0;
  }
  .risk-fill { height: 100%; border-radius: 9999px; }
  .risk-fill-CRITICAL { background: var(--crit); }
  .risk-fill-HIGH { background: var(--high); }
  .risk-fill-MEDIUM { background: var(--med); }
  .risk-fill-LOW { background: var(--low); }
  .risk-fill-INFORMATIONAL, .risk-fill-INFO { background: var(--info); }

  footer {
    border-top: 1px solid var(--border-subtle);
    padding-top: 1.75rem;
    margin-top: 3.5rem;
    font-size: 0.8125rem;
    color: var(--text-muted);
    text-align: center;
  }

  /* Interactive Attack Path Graph Styles */
  .attack-graph-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.6fr) minmax(290px, 1fr);
    gap: 1.25rem;
    margin-bottom: 1.25rem;
  }
  @media (max-width: 960px) {
    .attack-graph-grid {
      grid-template-columns: 1fr;
    }
  }
  .graph-canvas-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 6px;
    padding: 1.15rem;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .graph-canvas-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    padding-bottom: 0.65rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border-subtle);
  }
  .graph-canvas-title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .graph-canvas-label {
    font-size: 0.84rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
  }
  .graph-instructions {
    font-size: 0.76rem;
    color: var(--text-muted);
  }
  .svg-scroll-container {
    width: 100%;
    overflow-x: auto;
    overflow-y: hidden;
    padding: 0.5rem 0;
  }
  .svg-scroll-container::-webkit-scrollbar {
    height: 6px;
  }
  .svg-scroll-container::-webkit-scrollbar-thumb {
    background: var(--border-default);
    border-radius: 3px;
  }
  .graph-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 0.85rem;
    align-items: center;
    margin-top: 0.75rem;
    padding-top: 0.65rem;
    border-top: 1px solid var(--border-subtle);
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .legend-item {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
  }
  .legend-line {
    display: inline-block;
    width: 16px;
    height: 2px;
  }
  .legend-confirmed { background: var(--verified); }
  .legend-candidate {
    border-top: 2px dashed var(--med);
    background: transparent;
  }
  .legend-node {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 2px;
  }
  .legend-node-crit { background: var(--crit); }
  .legend-node-med { background: var(--med); }
  .legend-node-verified { background: var(--verified); }

  .graph-inspector-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 6px;
    padding: 1.15rem;
    display: flex;
    flex-direction: column;
    min-height: 240px;
  }
  .inspector-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 0.65rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border-subtle);
  }
  .inspector-title {
    font-size: 0.85rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-primary);
  }
  .inspector-reset-btn {
    background: transparent;
    border: 1px solid var(--border-subtle);
    color: var(--text-muted);
    font-size: 0.74rem;
    padding: 0.2rem 0.5rem;
    border-radius: 3px;
    cursor: pointer;
  }
  .inspector-reset-btn:hover {
    color: var(--text-primary);
    border-color: var(--border-default);
  }
  .inspector-body {
    flex: 1;
    display: flex;
    flex-direction: column;
    font-size: 0.88rem;
  }
  .inspector-field {
    margin-bottom: 0.6rem;
  }
  .inspector-label {
    display: block;
    font-size: 0.73rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    margin-bottom: 0.15rem;
  }
  .inspector-value {
    color: var(--text-primary);
    word-break: break-word;
  }
  .impact-value {
    color: var(--crit);
    font-weight: 600;
  }
  .warning-value {
    color: var(--med);
  }
  .inspector-item-title {
    font-size: 0.98rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.45rem;
  }
  .inspector-tip {
    margin-top: auto;
    font-size: 0.76rem;
    color: var(--text-muted);
    padding-top: 0.5rem;
    border-top: 1px dashed var(--border-subtle);
  }

  /* Interactive Graph SVG Element Styles */
  .graph-node-interactive {
    cursor: pointer;
    transition: filter 0.15s ease;
  }
  .graph-node-interactive:hover .node-bg {
    stroke-width: 2.5px;
    filter: drop-shadow(0 0 4px rgba(255,255,255,0.2));
  }
  .graph-node-interactive:focus {
    outline: none;
  }
  .graph-node-interactive:focus .node-bg,
  .graph-node-interactive.selected-node .node-bg {
    stroke-width: 3px !important;
    stroke: #ffffff !important;
    fill: var(--bg-elevated) !important;
  }
  .graph-edge-interactive {
    cursor: pointer;
  }
  .graph-edge-interactive:hover .edge-line {
    stroke-width: 3.5px;
  }
  .graph-edge-interactive:focus {
    outline: none;
  }
  .graph-edge-interactive:focus .edge-line,
  .graph-edge-interactive.selected-edge .edge-line {
    stroke-width: 3.5px !important;
    stroke: #ffffff !important;
  }
  .graph-edge-interactive:hover .edge-pill-bg,
  .graph-edge-interactive.selected-edge .edge-pill-bg {
    stroke: #ffffff !important;
    fill: #222222 !important;
  }

  /* Path Selector Tabs */
  .path-selector-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 1rem;
  }
  .path-tab-btn {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    padding: 0.35rem 0.8rem;
    font-size: 0.8rem;
    font-weight: 600;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .path-tab-btn:hover {
    color: var(--text-primary);
    border-color: var(--border-strong);
  }
  .path-tab-btn.active {
    background: var(--bg-elevated);
    color: var(--text-primary);
    border-color: var(--verified);
  }
  .hidden-path {
    display: none !important;
  }

  /* Empty Graph Card */
  .empty-graph-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 6px;
    padding: 2.25rem 1.75rem;
    text-align: center;
    margin-bottom: 1.5rem;
  }
  .empty-graph-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.45rem;
  }
  .empty-graph-desc {
    font-size: 0.88rem;
    color: var(--text-secondary);
    max-width: 620px;
    margin: 0 auto 0.65rem auto;
    line-height: 1.5;
  }
  .empty-graph-meta {
    font-size: 0.8rem;
    color: var(--text-muted);
  }

  /* Highlight target animation when navigating from graph */
  .highlight-target {
    animation: highlightPulse 2s ease;
  }
  @keyframes highlightPulse {
    0% { outline: 2px solid var(--verified); box-shadow: 0 0 12px var(--verified-bg); }
    100% { outline: 2px solid transparent; box-shadow: none; }
  }

  /* Print & PDF Stylesheet */
  @media print {
    :root, [data-theme="dark"], [data-theme="light"] {
      --bg-canvas: #ffffff !important;
      --bg-surface: #ffffff !important;
      --bg-elevated: #fafafa !important;
      --bg-subtle: #f4f4f5 !important;
      --border-subtle: #e4e4e7 !important;
      --border-default: #d4d4d8 !important;
      --border-strong: #a1a1aa !important;
      --text-primary: #09090b !important;
      --text-secondary: #3f3f46 !important;
      --text-muted: #71717a !important;
      --gauge-bg: #e4e4e7 !important;
    }
    body {
      background: #ffffff !important;
      color: #09090b !important;
      padding: 0 !important;
      font-size: 10.5pt !important;
    }
    .top-nav, .header-actions, .theme-toggle-btn, nav.toc, .copy-btn,
    .path-selector-tabs, .graph-instructions, .inspector-reset-btn, .inspector-tip {
      display: none !important;
    }
    .attack-graph-grid {
      display: block !important;
    }
    .graph-canvas-card {
      break-inside: avoid;
      page-break-inside: avoid;
      margin-bottom: 1rem;
      border: 1px solid #d4d4d8 !important;
      background: #ffffff !important;
    }
    .graph-inspector-card {
      display: none !important;
    }
    .svg-scroll-container {
      overflow: visible !important;
    }
    .hidden-path {
      display: block !important;
    }
    details, details.finding-card-details {
      display: block !important;
      border: 1px solid #d4d4d8 !important;
      margin-bottom: 0.75rem !important;
      break-inside: avoid;
      page-break-inside: avoid;
    }
    details summary {
      display: block !important;
      cursor: default !important;
      border-bottom: 1px solid #d4d4d8 !important;
    }
    details summary .chevron {
      display: none !important;
    }
    details .finding-body {
      display: block !important;
    }
    .card, .item-card, .narrative-box, .sub-box, .notice-box, .score-card {
      break-inside: avoid;
      page-break-inside: avoid;
      border: 1px solid #d4d4d8 !important;
      background: #ffffff !important;
    }
    pre, code, .code-snippet {
      white-space: pre-wrap !important;
      word-break: break-all !important;
    }
    @page {
      margin: 12mm 15mm;
      size: A4 portrait;
    }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Top Navigation Toolbar -->
  <div class="top-nav">
    <div class="brand-tag">FELIX SECURITY AUDITOR &bull; COMMERCIAL REPORT 2.0</div>
    <div class="header-actions">
      <button class="action-btn action-btn-pdf" onclick="exportPDF()" title="Export PDF / Print Dossier">
        <svg class="action-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        <span>Export PDF</span>
      </button>
      <button class="action-btn" id="themeToggleBtn" onclick="toggleTheme()" title="Toggle Theme">
        <svg id="themeIconSun" class="action-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
        <svg id="themeIconMoon" class="action-icon" style="display:none;" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <span id="themeToggleLabel">Light Mode</span>
      </button>
    </div>
  </div>

  <!-- Header -->
  <header>
    <div class="header-title">
      <h1>FELIX SECURITY AUDIT REPORT</h1>
      <div class="header-meta">
        <span>Target: <strong>{{.ExecutiveSummary.Target}}</strong></span>
        <span>Assessment Ref: <strong>{{.ExecutiveSummary.AssessmentID}}</strong></span>
        <span>Generated: <strong>{{.GeneratedAt}}</strong></span>
        <span>Schema Version: <strong>v{{.SchemaVersion}}</strong></span>
      </div>
    </div>

    <!-- Precision Exposure Score Card -->
    <div class="score-card">
      <div class="score-card-lbl">EXPOSURE SCORE</div>
      <div class="score-card-row">
        {{if or (not .ExecutiveSummary.RiskScoreAvailable) (eq .ExecutiveSummary.CompletionStatus "BLOCKED") (eq .ExecutiveSummary.CompletionStatus "FAILED") (eq .RiskOverview.RiskLevel "UNAVAILABLE")}}
        <div class="score-val" style="color: var(--crit);">N/A</div>
        <div class="score-verdict" style="color: var(--crit);">
          {{if eq .ExecutiveSummary.CompletionStatus "BLOCKED"}}BLOCKED{{else if eq .ExecutiveSummary.CompletionStatus "FAILED"}}FAILED{{else}}UNAVAILABLE{{end}}
        </div>
        {{else}}
        <div class="score-val color-{{.RiskOverview.RiskLevel}}">{{.RiskOverview.RiskScore}}</div>
        <div class="score-denom">/ 100</div>
        <div class="score-verdict color-{{.RiskOverview.RiskLevel}}">{{.RiskOverview.RiskLevel}} RISK</div>
        {{end}}
      </div>
      <div class="score-meter-track">
        <div class="score-meter-fill risk-fill-{{.RiskOverview.RiskLevel}}" style="width: {{if or (not .ExecutiveSummary.RiskScoreAvailable) (eq .ExecutiveSummary.CompletionStatus "BLOCKED") (eq .ExecutiveSummary.CompletionStatus "FAILED") (eq .RiskOverview.RiskLevel "UNAVAILABLE")}}0%{{else}}{{.RiskOverview.RiskScore}}%{{end}};"></div>
      </div>
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
    <div style="background: var(--crit-bg); border: 1px solid var(--crit-border); border-radius: 0.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: var(--crit);">
      <strong style="font-size: 1.05rem;">ASSESSMENT BLOCKED:</strong> Target presented access controls or automated challenge barriers (HTTP 403 / Cloudflare). Under Felix safe authorized audit rules, probes were halted. Security posture could not be evaluated.
    </div>
    {{else if eq .ExecutiveSummary.CompletionStatus "FAILED"}}
    <div style="background: var(--crit-bg); border: 1px solid var(--crit-border); border-radius: 0.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: var(--crit);">
      <strong style="font-size: 1.05rem;">ASSESSMENT FAILED:</strong> Target reachability could not be established due to network, transport, or server errors. Security posture could not be evaluated.
    </div>
    {{else if or (eq .ExecutiveSummary.CompletionStatus "PARTIAL") (eq .ExecutiveSummary.CompletionStatus "INCOMPLETE")}}
    <div style="background: var(--med-bg); border: 1px solid var(--med-border); border-radius: 0.5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: var(--med);">
      <strong style="font-size: 1.05rem;">PARTIAL ASSESSMENT:</strong> Assessment was incomplete. Some engines, targets, or checks were skipped or encountered errors. Results reflect only the completed portion of the assessment.
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
        <div class="card-val" style="color: var(--verified);">{{.ExecutiveSummary.FindingsVerifiedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Detected (Unverified)</div>
        <div class="card-val" style="color: var(--med);">{{.ExecutiveSummary.FindingsDetectedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Observations</div>
        <div class="card-val" style="color: var(--low);">{{.ExecutiveSummary.ObservationsCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Defended / Protected</div>
        <div class="card-val" style="color: var(--not-exposed);">{{.ExecutiveSummary.NotExposedChecksCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Inconclusive Checks</div>
        <div class="card-val" style="color: var(--text-muted);">{{.ExecutiveSummary.InconclusiveChecksCount}}</div>
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
      <div class="card card-crit">
        <div class="card-lbl">Critical</div>
        <div class="card-val color-CRITICAL">{{index .ExecutiveSummary.SeverityDistribution "CRITICAL"}}</div>
      </div>
      <div class="card card-high">
        <div class="card-lbl">High</div>
        <div class="card-val color-HIGH">{{index .ExecutiveSummary.SeverityDistribution "HIGH"}}</div>
      </div>
      <div class="card card-med">
        <div class="card-lbl">Medium</div>
        <div class="card-val color-MEDIUM">{{index .ExecutiveSummary.SeverityDistribution "MEDIUM"}}</div>
      </div>
      <div class="card card-low">
        <div class="card-lbl">Low</div>
        <div class="card-val color-LOW">{{index .ExecutiveSummary.SeverityDistribution "LOW"}}</div>
      </div>
      <div class="card card-info">
        <div class="card-lbl">Informational</div>
        <div class="card-val color-INFO">{{index .ExecutiveSummary.SeverityDistribution "INFO"}}</div>
      </div>
    </div>

    <h3>Key Evidence-Backed Concerns</h3>
    <ul class="clean-list">
      {{range .ExecutiveSummary.KeyConcerns}}
      <li class="clean-list-item"><span class="clean-list-dot" style="background: var(--high);"></span><span>{{.}}</span></li>
      {{end}}
    </ul>

    <h3>Assessment Limitations</h3>
    <ul class="clean-list">
      {{range .ExecutiveSummary.AssessmentLimitations}}
      <li class="clean-list-item"><span class="clean-list-dot"></span><span>{{.}}</span></li>
      {{end}}
    </ul>
  </section>

  <!-- 2. Assessment Scope -->
  <section id="section-scope">
    <h2>2. Assessment Scope</h2>
    <div class="item-card">
      <div class="item-meta">
        <span><strong>Provenance:</strong> {{.AssessmentScope.Provenance}}</span>
        <span><strong>Assessed Endpoints:</strong> {{.AssessmentScope.AssessedEndpointsCount}}</span>
        <span><strong>Discovered Endpoints:</strong> {{.AssessmentScope.DiscoveredEndpointsCount}}</span>
        {{if .AssessmentScope.Duration}}<span><strong>Duration:</strong> {{.AssessmentScope.Duration}}</span>{{end}}
      </div>

      <div class="sub-box">
        <div class="sub-box-title">In-Scope Domains & URLs</div>
        <ul class="clean-list" style="margin-bottom: 0;">
          {{range .AssessmentScope.InScopeURLs}}
          <li class="clean-list-item"><span class="clean-list-dot"></span><code>{{.}}</code></li>
          {{end}}
        </ul>
      </div>

      {{if .AssessmentScope.CloudResources}}
      <div class="sub-box">
        <div class="sub-box-title">Cloud & Database Resources in Scope</div>
        <ul class="clean-list" style="margin-bottom: 0;">
          {{range .AssessmentScope.CloudResources}}
          <li class="clean-list-item"><span class="clean-list-dot"></span><code>{{.}}</code></li>
          {{end}}
        </ul>
      </div>
      {{end}}

      {{if .AssessmentScope.AuthenticationContexts}}
      <div class="sub-box">
        <div class="sub-box-title">Authentication Contexts Evaluated</div>
        <ul class="clean-list" style="margin-bottom: 0;">
          {{range .AssessmentScope.AuthenticationContexts}}
          <li class="clean-list-item"><span class="clean-list-dot"></span><code>{{.}}</code></li>
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
        <ul class="clean-list" style="margin-bottom: 0;">
          {{range .AssessmentScope.ExplicitRestrictions}}
          <li class="clean-list-item"><span class="clean-list-dot"></span><code>{{.}}</code></li>
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

    <div class="table-wrapper">
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
    </div>
  </section>

  <!-- 4. Risk Overview -->
  <section id="section-risk-overview">
    <h2>4. Risk Overview</h2>
    <div class="narrative-box">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <span style="font-weight: 600;">Felix Deterministic Risk Meter (0–100)</span>
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
      <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-primary); margin-bottom: 0.35rem;">Formula Reconciliation</div>
      <code style="font-size: 0.85rem; color: var(--low);">{{.RiskOverview.ScoreBreakdown.Formula}}</code>
      <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.35rem;">
        Deterministic diminishing returns weights: 1.0&times; (1st), 0.5&times; (2nd), 0.3&times; (3rd), 0.2&times; (4th), 0.1&times; (subsequent). Hardening subtotal capped at 20.0 max. Correlated story bonuses capped at +15 max.
      </div>
    </div>

    {{if .RiskOverview.FindingRiskContributions}}
    <div class="table-wrapper">
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
          <td><span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span></td>
          <td style="text-align: right; font-weight: 600;">{{.Score}}</td>
          <td style="text-align: right; color: var(--text-secondary);">{{printf "%.1fx" .Weight}}</td>
          <td style="text-align: right; font-weight: 600; color: var(--verified);">{{printf "%.2f" .AdjustedScore}} pts</td>
        </tr>
        {{end}}
      </tbody>
      <tfoot>
        <tr style="font-weight: 600; background: var(--bg-elevated);">
          <td colspan="7" style="text-align: right;">Exposure Subtotal:</td>
          <td style="text-align: right; color: var(--verified);">{{printf "%.2f" .RiskOverview.ScoreBreakdown.ExposureSubtotal}} pts</td>
        </tr>
        <tr style="font-weight: 600; background: var(--bg-elevated);">
          <td colspan="7" style="text-align: right;">Hardening Subtotal (capped at 20):</td>
          <td style="text-align: right; color: var(--verified);">{{printf "%.2f" .RiskOverview.ScoreBreakdown.HardeningSubtotal}} pts</td>
        </tr>
        {{if gt .RiskOverview.ScoreBreakdown.StoryBonus 0.0}}
        <tr style="font-weight: 600; background: var(--bg-elevated);">
          <td colspan="7" style="text-align: right;">Correlated Story Bonus:</td>
          <td style="text-align: right; color: var(--low);">+{{printf "%.2f" .RiskOverview.ScoreBreakdown.StoryBonus}} pts</td>
        </tr>
        {{end}}
        <tr style="font-weight: 600; font-size: 0.95rem; background: var(--bg-subtle); border-top: 1px solid var(--border-default);">
          <td colspan="7" style="text-align: right;">Final Reconciled Score:</td>
          <td style="text-align: right; color: var(--text-primary);">{{.RiskOverview.ScoreBreakdown.TotalScore}} / 100</td>
        </tr>
      </tfoot>
    </table>
    </div>
    {{end}}

    {{if not .RiskOverview.AttackPaths}}
    <h3>Correlated Attack Paths (0)</h3>
    <div class="empty-graph-card">
      <div class="empty-graph-title">No Evidence-Supported Multi-Hop Attack Paths Detected</div>
      <p class="empty-graph-desc">
        Correlation analysis evaluated findings across the target boundary. No multi-hop exploit sequences (3+ hops) or causal transition chains met the empirical verification threshold for evidence-supported chaining.
      </p>
      <div class="empty-graph-meta">Individual component findings remain actionable in the verified and detected inventories below.</div>
    </div>
    {{else}}
    <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
      <h3 style="margin-bottom: 0;">Correlated Attack Paths ({{len .RiskOverview.AttackPaths}})</h3>
      <div style="font-size: 0.82rem; color: var(--text-muted);">Evidence-backed exploit chains synthesizing multiple vulnerabilities</div>
    </div>

    {{if gt (len .RiskOverview.AttackPaths) 1}}
    <!-- Path Selector Tabs -->
    <div class="path-selector-tabs" role="tablist" aria-label="Select Attack Path">
      {{range $i, $p := .RiskOverview.AttackPaths}}
      <button class="path-tab-btn {{if eq $i 0}}active{{end}}" role="tab" aria-selected="{{if eq $i 0}}true{{else}}false{{end}}" onclick="switchAttackPath({{$i}})">
        Path {{$i | add1}}: {{$p.Title}}
      </button>
      {{end}}
    </div>
    {{end}}

    {{range $idx, $p := .RiskOverview.AttackPaths}}
    <div id="path-view-{{$idx}}" class="path-view-wrapper {{if ne $idx 0}}hidden-path{{end}}" data-path-id="{{$p.ID}}">
      <!-- Hidden template containing pre-generated safe bash reproduction script -->
      <template id="reproduce-script-{{$p.ID}}">{{renderReproductionScript $p $.VerifiedFindings}}</template>
      <!-- Visual Attack Path Graph & Inspector Grid -->
      <div class="attack-graph-grid">
        <!-- Left: Interactive SVG Graph Canvas -->
        <div class="graph-canvas-card">
          <div class="graph-canvas-header">
            <div class="graph-canvas-title">
              <span class="graph-canvas-label">Exploit Chain Graph ({{len $p.NodeIDs}} Nodes)</span>
              <span class="badge badge-{{$p.Status}}">{{$p.Status}}</span>
              <span class="badge badge-{{$p.CombinedRiskLevel}}">{{severityBadge $p.CombinedRiskLevel}} ({{$p.CombinedRiskScore}}/100)</span>
            </div>
            <div class="graph-instructions" style="display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap;">
              <button class="action-btn" style="padding: 0.2rem 0.55rem; font-size: 0.78rem;" onclick="downloadReproductionScript('{{$p.ID}}')" title="Download standalone reproduction script (.sh)">
                <span>Export Script (.sh)</span>
              </button>
              <span>Click node or edge arrow for technical evidence</span>
            </div>
          </div>
          <div class="svg-scroll-container">
            {{renderAttackPathSVG $p}}
          </div>
          <!-- Graph Legend -->
          <div class="graph-legend">
            <span class="legend-item"><span class="legend-line legend-confirmed"></span> Confirmed</span>
            <span class="legend-item"><span class="legend-line legend-candidate"></span> Candidate</span>
            <span class="legend-item"><span class="legend-node legend-node-crit"></span> Crit / High</span>
            <span class="legend-item"><span class="legend-node legend-node-med"></span> Med / Low</span>
            <span class="legend-item"><span class="legend-node legend-node-verified"></span> Verified Status</span>
          </div>
        </div>

        <!-- Right: Attack Path Inspector Panel -->
        <div class="graph-inspector-card" id="inspector-{{$idx}}">
          <div class="inspector-header">
            <span class="inspector-title" id="inspector-title-{{$idx}}">Attack Path Overview</span>
            <button class="inspector-reset-btn" onclick="resetInspector({{$idx}})" title="Reset selection to path overview">Reset</button>
          </div>
          <div class="inspector-body" id="inspector-body-{{$idx}}">
            <div class="inspector-default-content">
              <div class="inspector-item-title">{{if $p.SyntheticFixture}}<span class="badge badge-INFO">[SYNTHETIC FIXTURE]</span> {{end}}{{$p.Title}}</div>
              <div class="inspector-field">
                <span class="inspector-label">Path Identifier</span>
                <span class="inspector-value"><code>{{$p.ID}}</code></span>
              </div>
              <div class="inspector-field">
                <span class="inspector-label">Terminal Impact</span>
                <span class="inspector-value impact-value">{{$p.TerminalImpact}}</span>
              </div>
              {{if $p.TargetAsset}}
              <div class="inspector-field">
                <span class="inspector-label">Target Asset</span>
                <span class="inspector-value"><code>{{$p.TargetAsset}}</code></span>
              </div>
              {{end}}
              {{if $p.EntryPoint}}
              <div class="inspector-field">
                <span class="inspector-label">Entry Point</span>
                <span class="inspector-value"><code>{{$p.EntryPoint}}</code></span>
              </div>
              {{end}}
              {{if $p.RiskRationale}}
              <div class="inspector-field">
                <span class="inspector-label">Risk Rationale</span>
                <span class="inspector-value">{{$p.RiskRationale}}</span>
              </div>
              {{end}}
              {{if $p.Assumptions}}
              <div class="inspector-field">
                <span class="inspector-label">Assumptions / Traversal Bounds</span>
                <span class="inspector-value warning-value">{{range $p.Assumptions}}{{.}} {{end}}</span>
              </div>
              {{end}}
              {{if $p.Remediation}}
              <div class="inspector-field">
                <span class="inspector-label">Choke Point Remediation</span>
                <span class="inspector-value" style="color: var(--verified); font-weight: 500;">{{$p.Remediation}}</span>
              </div>
              {{end}}
              <div class="inspector-tip">
                Tip: Click any node to inspect evidence or jump directly to its detailed audit inventory card.
              </div>
              <div style="margin-top: 0.85rem; padding-top: 0.75rem; border-top: 1px solid var(--border-default);">
                <button class="action-btn script-download-btn" style="width: 100%; justify-content: center; padding: 0.45rem 0.75rem; font-weight: 600;" onclick="downloadReproductionScript('{{$p.ID}}')" title="Download standalone sanitized Bash reproduction script">
                  <span>Download Reproduction Script (.sh)</span>
                </button>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.35rem; line-height: 1.35; text-align: center;">
                  Evidence-backed non-destructive curl verification procedure.
                </div>
              </div>
            </div>
          </div>
          <!-- Hidden template for resetting inspector -->
          <template class="inspector-default-content-template">
            <div class="inspector-default-content">
              <div class="inspector-item-title">{{if $p.SyntheticFixture}}<span class="badge badge-INFO">[SYNTHETIC FIXTURE]</span> {{end}}{{$p.Title}}</div>
              <div class="inspector-field">
                <span class="inspector-label">Path Identifier</span>
                <span class="inspector-value"><code>{{$p.ID}}</code></span>
              </div>
              <div class="inspector-field">
                <span class="inspector-label">Terminal Impact</span>
                <span class="inspector-value impact-value">{{$p.TerminalImpact}}</span>
              </div>
              {{if $p.TargetAsset}}
              <div class="inspector-field">
                <span class="inspector-label">Target Asset</span>
                <span class="inspector-value"><code>{{$p.TargetAsset}}</code></span>
              </div>
              {{end}}
              {{if $p.EntryPoint}}
              <div class="inspector-field">
                <span class="inspector-label">Entry Point</span>
                <span class="inspector-value"><code>{{$p.EntryPoint}}</code></span>
              </div>
              {{end}}
              {{if $p.RiskRationale}}
              <div class="inspector-field">
                <span class="inspector-label">Risk Rationale</span>
                <span class="inspector-value">{{$p.RiskRationale}}</span>
              </div>
              {{end}}
              {{if $p.Assumptions}}
              <div class="inspector-field">
                <span class="inspector-label">Assumptions / Traversal Bounds</span>
                <span class="inspector-value warning-value">{{range $p.Assumptions}}{{.}} {{end}}</span>
              </div>
              {{end}}
              {{if $p.Remediation}}
              <div class="inspector-field">
                <span class="inspector-label">Choke Point Remediation</span>
                <span class="inspector-value" style="color: var(--verified); font-weight: 500;">{{$p.Remediation}}</span>
              </div>
              {{end}}
              <div class="inspector-tip">
                Tip: Click any node to inspect evidence or jump directly to its detailed audit inventory card.
              </div>
              <div style="margin-top: 0.85rem; padding-top: 0.75rem; border-top: 1px solid var(--border-default);">
                <button class="action-btn script-download-btn" style="width: 100%; justify-content: center; padding: 0.45rem 0.75rem; font-weight: 600;" onclick="downloadReproductionScript('{{$p.ID}}')" title="Download standalone sanitized Bash reproduction script">
                  <span>Download Reproduction Script (.sh)</span>
                </button>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.35rem; line-height: 1.35; text-align: center;">
                  Evidence-backed non-destructive curl verification procedure.
                </div>
              </div>
            </div>
          </template>
        </div>
      </div>

      <!-- Preserved Item Card Narrative & Fallback -->
      <div class="item-card">
        <div class="item-header">
          <div class="item-title">{{$p.Title}}</div>
          <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="badge badge-{{$p.CombinedRiskLevel}}">{{severityBadge $p.CombinedRiskLevel}} ({{$p.CombinedRiskScore}}/100)</span>
            <span class="badge badge-INFO">{{$p.Status}}</span>
            {{if $p.SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
          </div>
        </div>
        <p style="font-size: 0.92rem; margin-bottom: 0.75rem;">{{$p.RiskRationale}}</p>
        {{if $p.Transitions}}
        <div class="sub-box">
          <div class="sub-box-title">Attack Transitions</div>
          <ul class="clean-list" style="margin-bottom: 0;">
            {{range $p.Transitions}}
            <li class="clean-list-item"><span class="clean-list-dot"></span><span>{{.}}</span></li>
            {{end}}
          </ul>
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
    {{end}}

    {{if .RiskOverview.RiskConcentrations}}
    <h3>Risk Concentration by Component</h3>
    <div class="table-wrapper">
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
          <td><span class="badge badge-{{.RiskLevel}}">{{severityBadge .RiskLevel}}</span></td>
          <td>{{.Score}}</td>
          <td>{{.Count}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    </div>
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
    <details id="finding-{{.ID}}" class="finding-card-details finding-item" data-severity="{{.Severity}}" data-verification="VERIFIED">
      <summary class="finding-summary-row">
        <div class="finding-header-left">
          <span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span>
          <span class="item-title">[{{.ID}}] {{.Title}}</span>
        </div>
        <div class="finding-header-right">
          <span class="badge badge-VERIFIED">VERIFIED</span>
          <span class="badge badge-INFO">Det Conf: {{.Confidence.DetectionConfidence}}</span>
          <span class="badge badge-INFO">Ver Conf: {{.Confidence.VerificationConfidence}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
          {{if and .Framework (ne .Framework "generic")}}<span class="badge" style="background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border);">{{.Framework}}{{if .FrameworkVersion}} v{{.FrameworkVersion}}{{end}}</span>{{end}}
          <span class="chevron" aria-hidden="true"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></span>
        </div>
      </summary>

      <div class="finding-body">
        <div class="item-meta">
          <span><strong>Affected Asset:</strong> <code>{{.AffectedAsset}}</code></span>
          <span><strong>Location:</strong> <code>{{.AssetLocation}}</code></span>
          {{if and .Framework (ne .Framework "generic")}}<span><strong>Framework:</strong> {{.Framework}}{{if .FrameworkVersion}} (v{{.FrameworkVersion}}){{end}}</span>{{end}}
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
          <div style="font-size: 0.85rem; color: var(--verified); margin-bottom: 0.4rem;">
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
          <div class="evidence-header-row">
            <span class="sub-box-title" style="margin-bottom:0;">Supporting Evidence (Sanitized)</span>
            {{if .Evidence.SafeCurlCommand}}<button class="copy-btn" onclick="copyEvidence(this, 'vf-curl-{{.ID}}')">Copy Curl</button>{{end}}
          </div>
          <p style="font-size: 0.9rem; margin-top: 0.35rem;">{{.Evidence.Observation}}</p>
          {{if .Evidence.HTTPStatus}}
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
            HTTP Response Status: <strong>{{.Evidence.HTTPStatus}}</strong> {{if .Evidence.HTTPMethod}}({{.Evidence.HTTPMethod}}){{end}}
          </p>
          {{end}}
          {{if .Evidence.SafeCurlCommand}}
          <div style="margin-top: 0.5rem;">
            <span style="font-size: 0.78rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Safe Reproduction:</span>
            <div class="code-snippet" id="vf-curl-{{.ID}}">{{.Evidence.SafeCurlCommand}}</div>
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
    </details>
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
    <details id="finding-{{.ID}}" class="finding-card-details finding-item" data-severity="{{.Severity}}" data-verification="{{.Verification.Status}}">
      <summary class="finding-summary-row">
        <div class="finding-header-left">
          <span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span>
          <span class="item-title">[{{.ID}}] {{.Title}}</span>
        </div>
        <div class="finding-header-right">
          <span class="badge badge-{{.Verification.Status}}">{{.Verification.Status}}</span>
          <span class="badge badge-INFO">Det Conf: {{.Confidence.DetectionConfidence}}</span>
          <span class="badge badge-INFO">Ver Conf: {{.Confidence.VerificationConfidence}}</span>
          {{if .SyntheticFixture}}<span class="badge badge-SYNTHETIC">[SYNTHETIC FIXTURE]</span>{{end}}
          {{if and .Framework (ne .Framework "generic")}}<span class="badge" style="background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border);">{{.Framework}}{{if .FrameworkVersion}} v{{.FrameworkVersion}}{{end}}</span>{{end}}
          <span class="chevron" aria-hidden="true"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></span>
        </div>
      </summary>

      <div class="finding-body">
        <div class="item-meta">
          <span><strong>Affected Asset:</strong> <code>{{.AffectedAsset}}</code></span>
          {{if and .Framework (ne .Framework "generic")}}<span><strong>Framework:</strong> {{.Framework}}{{if .FrameworkVersion}} (v{{.FrameworkVersion}}){{end}}</span>{{end}}
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
          <div style="font-size: 0.85rem; color: var(--med); margin-top: 0.4rem;">
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
    </details>
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
    <div class="table-wrapper">
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
    </div>
    {{end}}

    <h3>Complete Finding Traceability Index</h3>
    <div class="table-wrapper">
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
          <td><span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span></td>
          <td><span class="badge badge-{{.CanonicalStatus}}">{{.CanonicalStatus}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    </div>

    <h3>Engine Execution Metrics</h3>
    <div class="table-wrapper">
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
    </div>

    <h3>Correlation Rules Catalog</h3>
    <ul class="clean-list">
      {{range .TechnicalAppendix.CorrelationRulesEvaluated}}
      <li class="clean-list-item"><span class="clean-list-dot"></span><span>{{.}}</span></li>
      {{end}}
    </ul>
  </section>

  <!-- Footer -->
  <footer>
    <p>Generated by <strong>Felix Security Auditor</strong> &bull; Commercial Report 2.0 Specification &bull; Confidential Assessment Document</p>
    <p style="margin-top: 0.25rem; font-size: 0.78rem;">Note: Remediation recommendations are excluded from Stage 12 and reserved for Remediation Intelligence 3.0.</p>
  </footer>

</div>

<script>
  function initTheme() {
    var saved = localStorage.getItem('felix-report-theme');
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var theme = saved ? saved : (prefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeButton(theme);
  }

  function toggleTheme() {
    var cur = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('felix-report-theme', next); } catch(e) {}
    updateThemeButton(next);
  }

  function updateThemeButton(theme) {
    var lbl = document.getElementById('themeToggleLabel');
    if (lbl) {
      lbl.innerText = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
    }
    var sun = document.getElementById('themeIconSun');
    var moon = document.getElementById('themeIconMoon');
    if (sun && moon) {
      if (theme === 'dark') {
        sun.style.display = 'inline-block';
        moon.style.display = 'none';
      } else {
        sun.style.display = 'none';
        moon.style.display = 'inline-block';
      }
    }
  }

  function exportPDF() {
    var details = document.querySelectorAll('details');
    details.forEach(function(d) { d.setAttribute('open', 'true'); });
    window.print();
  }

  function copyEvidence(btn, elId) {
    var el = document.getElementById(elId);
    if (!el) return;
    var text = el.innerText || el.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        var orig = btn.innerText;
        btn.innerText = 'Copied';
        btn.classList.add('copied');
        setTimeout(function() {
          btn.innerText = orig;
          btn.classList.remove('copied');
        }, 2000);
      }).catch(function() {
        fallbackCopy(text, btn);
      });
    } else {
      fallbackCopy(text, btn);
    }
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      var orig = btn.innerText;
      btn.innerText = 'Copied';
      btn.classList.add('copied');
      setTimeout(function() {
        btn.innerText = orig;
        btn.classList.remove('copied');
      }, 2000);
    } catch(err) {}
    document.body.removeChild(ta);
  }

  function switchAttackPath(idx) {
    document.querySelectorAll('.path-tab-btn').forEach(function(b, i) {
      if (i === idx) {
        b.classList.add('active');
        b.setAttribute('aria-selected', 'true');
      } else {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      }
    });
    document.querySelectorAll('.path-view-wrapper').forEach(function(view, i) {
      if (i === idx) {
        view.classList.remove('hidden-path');
      } else {
        view.classList.add('hidden-path');
      }
    });
  }

  function selectGraphNode(pathId, nodeId) {
    var activeView = (pathId ? document.querySelector('.path-view-wrapper[data-path-id="' + pathId + '"]') : null) || document.querySelector('.path-view-wrapper:not(.hidden-path)');
    if (!activeView) return;
    var svg = activeView.querySelector('svg');
    if (!svg) return;

    svg.querySelectorAll('.graph-node-interactive').forEach(function(el) { el.classList.remove('selected-node'); });
    svg.querySelectorAll('.graph-edge-interactive').forEach(function(el) { el.classList.remove('selected-edge'); });

    var nodeEl = svg.querySelector('.graph-node-interactive[data-node-id="' + nodeId + '"]');
    if (nodeEl) {
      nodeEl.classList.add('selected-node');
    }

    var title = nodeEl ? nodeEl.getAttribute('data-title') : nodeId;
    var sev = nodeEl ? nodeEl.getAttribute('data-severity') : '';
    var ver = nodeEl ? nodeEl.getAttribute('data-verification') : '';
    var cat = nodeEl ? nodeEl.getAttribute('data-category') : '';
    var ep = nodeEl ? nodeEl.getAttribute('data-endpoint') : '';
    var ev = nodeEl ? nodeEl.getAttribute('data-evidence') : '';

    var inspectorBody = activeView.querySelector('.inspector-body');
    var inspectorTitle = activeView.querySelector('.inspector-title');

    if (inspectorTitle) {
      inspectorTitle.textContent = 'Node: [' + nodeId + ']';
    }

    if (inspectorBody) {
      var htmlStr = '<div class="inspector-detail-content">';
      htmlStr += '<div class="inspector-item-title">' + escapeHTML(title) + '</div>';
      htmlStr += '<div style="display:flex; gap:0.4rem; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap;">';
      if (sev) htmlStr += '<span class="badge badge-' + escapeHTML(sev) + '">' + escapeHTML(sev) + '</span>';
      if (ver) htmlStr += '<span class="badge badge-' + escapeHTML(ver) + '">' + escapeHTML(ver) + '</span>';
      if (cat) htmlStr += '<span class="badge badge-INFO">' + escapeHTML(cat) + '</span>';
      htmlStr += '</div>';

      if (ep) {
        htmlStr += '<div class="inspector-field"><span class="inspector-label">Endpoint / Target</span><span class="inspector-value"><code>' + escapeHTML(ep) + '</code></span></div>';
      }
      if (ev) {
        htmlStr += '<div class="inspector-field"><span class="inspector-label">Sanitized Technical Evidence</span><div class="evidence-box" style="margin-top:0.25rem; max-height:160px; overflow-y:auto; font-size:0.82rem;">' + escapeHTML(ev) + '</div></div>';
      }

      htmlStr += '<div style="margin-top:0.85rem; padding-top:0.75rem; border-top:1px solid var(--border-default); display:flex; gap:0.5rem;">';
      htmlStr += '<button class="action-btn" style="width:100%; justify-content:center; padding:0.45rem 0.75rem;" onclick="navigateToFinding(\'' + escapeHTML(nodeId) + '\')">';
      htmlStr += '<span>Inspect Full Finding in Inventory &rarr;</span></button>';
      htmlStr += '</div>';
      htmlStr += '</div>';

      inspectorBody.innerHTML = htmlStr;
    }
  }

  function selectGraphEdge(pathId, edgeIdx) {
    var activeView = (pathId ? document.querySelector('.path-view-wrapper[data-path-id="' + pathId + '"]') : null) || document.querySelector('.path-view-wrapper:not(.hidden-path)');
    if (!activeView) return;
    var svg = activeView.querySelector('svg');
    if (!svg) return;

    svg.querySelectorAll('.graph-node-interactive').forEach(function(el) { el.classList.remove('selected-node'); });
    svg.querySelectorAll('.graph-edge-interactive').forEach(function(el) { el.classList.remove('selected-edge'); });

    var edges = svg.querySelectorAll('.graph-edge-interactive');
    var edgeEl = edges[edgeIdx];
    if (edgeEl) {
      edgeEl.classList.add('selected-edge');
    }

    var srcId = edgeEl ? edgeEl.getAttribute('data-source-id') : '';
    var tgtId = edgeEl ? edgeEl.getAttribute('data-target-id') : '';
    var srcTitle = edgeEl ? edgeEl.getAttribute('data-source-title') : '';
    var tgtTitle = edgeEl ? edgeEl.getAttribute('data-target-title') : '';
    var rule = edgeEl ? edgeEl.getAttribute('data-rule') : '';
    var ruleName = edgeEl ? edgeEl.getAttribute('data-rule-name') : '';
    var status = edgeEl ? edgeEl.getAttribute('data-status') : '';
    var conf = edgeEl ? edgeEl.getAttribute('data-confidence') : '';
    var expl = edgeEl ? edgeEl.getAttribute('data-explanation') : '';

    var inspectorBody = activeView.querySelector('.inspector-body');
    var inspectorTitle = activeView.querySelector('.inspector-title');

    if (inspectorTitle) {
      inspectorTitle.textContent = 'Transition: ' + (rule || 'Causal Edge');
    }

    if (inspectorBody) {
      var htmlStr = '<div class="inspector-detail-content">';
      htmlStr += '<div class="inspector-item-title">' + escapeHTML(srcTitle || srcId) + ' &rarr; ' + escapeHTML(tgtTitle || tgtId) + '</div>';
      htmlStr += '<div style="display:flex; gap:0.4rem; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap;">';
      if (rule) htmlStr += '<span class="badge badge-INFO">' + escapeHTML(rule) + '</span>';
      if (status) htmlStr += '<span class="badge badge-' + escapeHTML(status) + '">' + escapeHTML(status) + '</span>';
      if (conf) htmlStr += '<span class="badge badge-INFO">Conf: ' + escapeHTML(conf) + '</span>';
      htmlStr += '</div>';

      if (ruleName) {
        htmlStr += '<div class="inspector-field"><span class="inspector-label">Correlation Rule</span><span class="inspector-value">' + escapeHTML(ruleName) + '</span></div>';
      }
      if (expl) {
        htmlStr += '<div class="inspector-field"><span class="inspector-label">Causal Transition Explanation</span><div class="evidence-box" style="margin-top:0.25rem; font-size:0.85rem; line-height:1.45;">' + escapeHTML(expl) + '</div></div>';
      }

      htmlStr += '<div style="margin-top:0.85rem; padding-top:0.75rem; border-top:1px solid var(--border-default); display:flex; gap:0.5rem;">';
      htmlStr += '<button class="action-btn" style="flex:1; justify-content:center; padding:0.4rem;" onclick="navigateToFinding(\'' + escapeHTML(srcId) + '\')">Source [' + escapeHTML(srcId) + ']</button>';
      htmlStr += '<button class="action-btn" style="flex:1; justify-content:center; padding:0.4rem;" onclick="navigateToFinding(\'' + escapeHTML(tgtId) + '\')">Target [' + escapeHTML(tgtId) + ']</button>';
      htmlStr += '</div>';
      htmlStr += '</div>';

      inspectorBody.innerHTML = htmlStr;
    }
  }

  function resetInspector(idx) {
    var view = document.getElementById('path-view-' + idx);
    if (!view) return;

    var svg = view.querySelector('svg');
    if (svg) {
      svg.querySelectorAll('.graph-node-interactive').forEach(function(el) { el.classList.remove('selected-node'); });
      svg.querySelectorAll('.graph-edge-interactive').forEach(function(el) { el.classList.remove('selected-edge'); });
    }

    var defContent = view.querySelector('.inspector-default-content-template');
    var inspectorBody = view.querySelector('.inspector-body');
    var inspectorTitle = view.querySelector('.inspector-title');

    if (inspectorTitle) {
      inspectorTitle.textContent = 'Attack Path Overview';
    }
    if (defContent && inspectorBody) {
      inspectorBody.innerHTML = defContent.innerHTML;
    }
  }

  function handleGraphKey(event, type, pathId, id) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      if (type === 'node') selectGraphNode(pathId, id);
      else if (type === 'edge') selectGraphEdge(pathId, id);
    }
  }

  function navigateToFinding(findingId) {
    var el = document.getElementById('finding-' + findingId);
    if (el) {
      el.open = true;
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('highlight-target');
      setTimeout(function() { el.classList.remove('highlight-target'); }, 2500);
    }
  }

  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function downloadReproductionScript(pathId) {
    var tmpl = document.getElementById('reproduce-script-' + pathId);
    if (!tmpl) {
      alert('Reproduction script is not available for this chain.');
      return;
    }
    var rawText = (tmpl.content && tmpl.content.textContent) ? tmpl.content.textContent : (tmpl.textContent || tmpl.innerText);
    if (!rawText && tmpl.innerHTML) {
      var ta = document.createElement('textarea');
      ta.innerHTML = tmpl.innerHTML;
      rawText = ta.value;
    }

    var cleanId = (pathId || 'chain').replace(/[^a-zA-Z0-9_-]/g, '_');
    var filename = 'reproduce_chain_' + cleanId + '.sh';

    var blob = new Blob([rawText], { type: 'application/x-sh;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function() { URL.revokeObjectURL(url); }, 2000);
  }

  document.addEventListener('DOMContentLoaded', initTheme);
</script>
</body>
</html>`

// GenerateCommercialHTML renders a CommercialReport struct into an offline HTML document.
func GenerateCommercialHTML(cr CommercialReport) (string, error) {
	var fallbackFindings []Finding
	for _, f := range cr.VerifiedFindings {
		ep := f.AssetLocation
		if ep == "" {
			ep = f.AffectedAsset
		}
		fallbackFindings = append(fallbackFindings, Finding{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Category: f.Category,
			Endpoint: ep,
			Evidence: f.Evidence.EvidenceSummary,
		})
	}
	for _, f := range cr.DetectedFindings {
		ep := f.AssetLocation
		if ep == "" {
			ep = f.AffectedAsset
		}
		fallbackFindings = append(fallbackFindings, Finding{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Category: f.Category,
			Endpoint: ep,
			Evidence: f.Evidence.EvidenceSummary,
		})
	}
	for i := range cr.RiskOverview.AttackPaths {
		if len(cr.RiskOverview.AttackPaths[i].GraphNodes) == 0 {
			EnrichAttackPathGraph(&cr.RiskOverview.AttackPaths[i], fallbackFindings)
		}
	}

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"add1": func(i int) int {
			return i + 1
		},
		"renderAttackPathSVG": func(path AttackPathSummary) template.HTML {
			return RenderAttackPathSVG(path)
		},
		"renderReproductionScript": func(path AttackPathSummary, findings []CommercialFinding) string {
			var rf []Finding
			for _, f := range findings {
				ep := f.AssetLocation
				if ep == "" {
					ep = f.AffectedAsset
				}
				rf = append(rf, Finding{
					ID:       f.ID,
					Title:    f.Title,
					Severity: f.Severity,
					Category: f.Category,
					Endpoint: ep,
					Method:   f.DetectionMethod,
					Evidence: f.Evidence.EvidenceSummary,
				})
			}
			plan, err := GenerateReproductionScript(path, rf, ReproductionOptions{})
			if err != nil {
				return ""
			}
			return SanitizeEvidence(plan.ShellScriptContent)
		},
		"gaugeOffset": func(score int, available bool) string {
			if !available || score < 0 {
				return "326.73"
			}
			if score > 100 {
				score = 100
			}
			offset := 326.73 - (float64(score)/100.0)*326.73
			return fmt.Sprintf("%.2f", offset)
		},
		"gaugeColor": func(level string, status string) string {
			switch status {
			case "BLOCKED", "FAILED":
				return "#ef4444"
			}
			switch level {
			case "CRITICAL", "CRIT":
				return "#ef4444"
			case "HIGH":
				return "#f97316"
			case "MEDIUM", "MED":
				return "#eab308"
			case "LOW":
				return "#3b82f6"
			case "INFORMATIONAL", "INFO":
				return "#64748b"
			default:
				return "#10b981"
			}
		},
		"severityBadge": func(sev string) string {
			s := strings.ToUpper(strings.TrimSpace(sev))
			switch s {
			case "CRITICAL", "CRIT":
				return "[CRIT]"
			case "HIGH":
				return "[HIGH]"
			case "MEDIUM", "MED":
				return "[MED]"
			case "LOW":
				return "[LOW]"
			case "INFORMATIONAL", "INFO":
				return "[INFO]"
			default:
				return fmt.Sprintf("[%s]", s)
			}
		},
	}

	tmpl, err := template.New("felix-commercial-report").Funcs(funcMap).Parse(commercialHTMLReportTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cr); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WriteCommercialHTML writes the self-contained CommercialReport HTML document to disk with restricted permissions (0600).
func WriteCommercialHTML(cr CommercialReport, filePath string) error {
	content, err := GenerateCommercialHTML(cr)
	if err != nil {
		return err
	}
	return writeReportFileSafely(filePath, []byte(content))
}
