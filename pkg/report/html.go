package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Felix Security Assessment Report — {{.Target}}</title>
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
    --defended: #2dd4bf;
    --defended-bg: rgba(45, 212, 191, 0.10);
    --defended-border: rgba(45, 212, 191, 0.28);
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
    --defended: #0d9488;
    --defended-bg: #ccfbf1;
    --defended-border: #5eead4;
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
  .container { max-width: 1200px; margin: 0 auto; }

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
  .color-CRITICAL, .color-CRIT { color: var(--crit); }
  .color-HIGH { color: var(--high); }
  .color-MEDIUM, .color-MED { color: var(--med); }
  .color-LOW { color: var(--low); }
  .color-INFORMATIONAL, .color-INFO { color: var(--info); }

  /* Sections */
  section { margin-bottom: 2.75rem; }
  h2 {
    font-size: 1.1875rem;
    font-weight: 600;
    margin-bottom: 1.25rem;
    padding-bottom: 0.65rem;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    letter-spacing: -0.02em;
    display: flex;
    justify-content: space-between;
    align-items: center;
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

  /* Grid & Metric Cards */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 0.95rem 1.15rem;
    position: relative;
    transition: border-color 0.15s ease;
  }
  .card:hover { border-color: var(--border-strong); }
  .card-lbl {
    font-size: 0.6875rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 500;
    margin-bottom: 0.35rem;
  }
  .card-val {
    font-size: 1.5rem;
    font-weight: 600;
    margin-top: 0.25rem;
    line-height: 1.1;
    color: var(--text-primary);
    letter-spacing: -0.02em;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  .card.card-crit { border-top: 2px solid var(--crit); }
  .card.card-high { border-top: 2px solid var(--high); }
  .card.card-med { border-top: 2px solid var(--med); }
  .card.card-low { border-top: 2px solid var(--low); }
  .card.card-info { border-top: 2px solid var(--info); }

  /* Badges */
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    line-height: 1.2;
  }
  .badge-CRITICAL, .badge-CRIT { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }
  .badge-HIGH { background: var(--high-bg); color: var(--high); border: 1px solid var(--high-border); }
  .badge-MEDIUM, .badge-MED { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge-LOW { background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }
  .badge-INFO, .badge-INFORMATIONAL { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

  .badge-VERIFIED { background: var(--verified-bg); color: var(--verified); border: 1px solid var(--verified-border); }
  .badge-CANDIDATE { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge-INCONCLUSIVE { background: var(--bg-elevated); color: var(--text-muted); border: 1px solid var(--border-default); }
  .badge-DETECTED { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge-EVIDENCE_SUPPORTED, .badge-OBSERVED { background: var(--bg-elevated); color: var(--text-secondary); border: 1px solid var(--border-default); }
  .badge-NOT_VERIFIED { background: var(--bg-elevated); color: var(--text-muted); border: 1px solid var(--border-default); }
  .badge-NOT_EXPOSED, .badge-DEFENDED { background: var(--defended-bg); color: var(--defended); border: 1px solid var(--defended-border); }
  .badge-CONFIRMED { background: var(--verified-bg); color: var(--verified); border: 1px solid var(--verified-border); }
  .badge-SUSPECTED { background: var(--med-bg); color: var(--med); border: 1px solid var(--med-border); }
  .badge-NOT_TESTED { background: var(--bg-elevated); color: var(--text-muted); border: 1px solid var(--border-default); }
  .badge-ERROR { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-border); }
  .badge-STATIC_ANALYSIS { background: rgba(99, 102, 241, 0.12); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); }
  .badge-ACTIVE_VERIFICATION { background: var(--verified-bg); color: var(--verified); border: 1px solid var(--verified-border); }
  .badge-MANUAL_REVIEW { background: rgba(168, 85, 247, 0.12); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }

  /* Narrative Boxes */
  .summary-narrative {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 1.15rem 1.35rem;
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }
  .summary-narrative p + p { margin-top: 0.75rem; }
  .summary-narrative strong { color: var(--text-primary); font-weight: 600; }

  /* Risk Bar */
  .risk-bar-container {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 1.15rem 1.25rem;
    margin-bottom: 2rem;
  }
  .risk-bar-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
    color: var(--text-secondary);
    font-weight: 600;
  }
  .risk-track {
    height: 6px;
    background-color: var(--gauge-bg);
    border-radius: 9999px;
    overflow: hidden;
    position: relative;
  }
  .risk-fill {
    height: 100%;
    border-radius: 9999px;
    transition: width 0.3s ease;
  }
  .risk-fill-CRITICAL { background: var(--crit); }
  .risk-fill-HIGH { background: var(--high); }
  .risk-fill-MEDIUM { background: var(--med); }
  .risk-fill-LOW { background: var(--low); }
  .risk-fill-INFORMATIONAL, .risk-fill-INFO { background: var(--info); }

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

  /* Defensive Boundaries Section */
  .defensive-section-box {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-left: 3px solid var(--defended);
    border-radius: 8px;
    padding: 1.25rem 1.35rem;
    margin-bottom: 2rem;
  }
  .defensive-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
    flex-wrap: wrap;
  }
  .defensive-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text-primary);
  }
  .defensive-badge {
    background: var(--defended-bg);
    color: var(--defended);
    border: 1px solid var(--defended-border);
    font-weight: 600;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.72rem;
    letter-spacing: 0.04em;
  }
  .defensive-desc {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-bottom: 1rem;
    line-height: 1.6;
  }

  /* Attack Path Visualization Flow */
  .attack-flow-diagram {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
    padding: 1rem 1.25rem;
    margin: 0.85rem 0;
  }
  .flow-node {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 2px;
    padding: 0.5rem 0.85rem;
    min-width: 150px;
    flex: 1;
  }
  .flow-node-badge {
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.2rem;
  }
  .flow-node-title {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-primary);
    word-break: break-all;
  }
  .flow-arrow {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
  }

  /* Expandable Finding Cards */
  .finding-card-details {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
    margin-bottom: 0.75rem;
    overflow: hidden;
    transition: border-color 0.15s ease;
  }
  .finding-card-details:hover { border-color: var(--border-strong); }
  .finding-summary-row {
    padding: 0.85rem 1.15rem;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.92rem;
    color: var(--text-primary);
    list-style: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
    gap: 0.75rem;
    flex-wrap: wrap;
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
    padding: 1.15rem;
    font-size: 0.88rem;
    color: var(--text-secondary);
  }

  /* Item & Story Cards */
  .item-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 3px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
    transition: border-color 0.15s ease;
  }
  .item-card:hover { border-color: var(--border-strong); }
  .item-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.75rem;
    flex-wrap: wrap;
  }
  .item-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1.3;
  }
  .item-meta {
    font-size: 0.82rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
    word-break: break-all;
  }
  .item-meta strong { color: var(--text-primary); }

  .item-desc {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-bottom: 0.85rem;
    line-height: 1.55;
  }

  /* Code Snippets & Copy Button */
  .evidence-header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.35rem;
  }
  .code-snippet {
    background-color: var(--bg-canvas);
    border: 1px solid var(--border-subtle);
    border-radius: 2px;
    padding: 0.75rem 0.95rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.82rem;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-all;
    margin-bottom: 0.75rem;
    position: relative;
  }
  .copy-btn {
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    padding: 0.2rem 0.55rem;
    border-radius: 2px;
    font-size: 0.72rem;
    font-weight: 600;
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

  .verification-block {
    background-color: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-left: 3px solid var(--verified);
    border-radius: 0 2px 2px 0;
    padding: 0.65rem 0.95rem;
    font-size: 0.85rem;
    color: var(--text-primary);
    margin-bottom: 0.75rem;
  }
  .verification-block strong { color: var(--verified); }

  .negative-block, .negative-evidence-box {
    background-color: var(--defended-bg);
    border-left: 3px solid var(--defended);
    border-radius: 0 2px 2px 0;
    padding: 0.65rem 0.95rem;
    font-size: 0.85rem;
    color: var(--defended);
    margin-bottom: 0.75rem;
  }
  .negative-block strong, .negative-evidence-box strong { color: var(--defended); font-weight: 700; }

  .investigate-block {
    background-color: rgba(168, 85, 247, 0.1);
    border-left: 3px solid #a855f7;
    border-radius: 0 2px 2px 0;
    padding: 0.65rem 0.95rem;
    font-size: 0.88rem;
    color: #d8b4fe;
    margin-bottom: 0.75rem;
  }
  .investigate-block strong { color: #f3e8ff; }

  .remediation-block {
    background-color: var(--low-bg);
    border-left: 3px solid var(--low);
    border-radius: 0 2px 2px 0;
    padding: 0.65rem 0.95rem;
    font-size: 0.88rem;
    color: var(--text-primary);
  }
  .remediation-block strong { color: var(--low); }

  .story-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-left: 3px solid var(--low);
    border-radius: 3px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
  }
  .story-list {
    padding-left: 1.25rem;
    font-size: 0.88rem;
    color: var(--text-secondary);
    margin: 0.5rem 0 0.85rem 0;
  }
  .story-list li { margin-bottom: 0.3rem; }

  /* Interactive Filters */
  .filter-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    align-items: center;
    margin-bottom: 1.25rem;
  }
  .filter-btn {
    background-color: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    padding: 0.35rem 0.7rem;
    border-radius: 2px;
    font-size: 0.78rem;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.15s ease;
  }
  .filter-btn:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }
  .filter-btn.active {
    background-color: var(--bg-subtle);
    border-color: var(--border-strong);
    color: var(--text-primary);
  }
  .search-box {
    background-color: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-primary);
    padding: 0.35rem 0.7rem;
    border-radius: 2px;
    font-size: 0.82rem;
    margin-left: auto;
    min-width: 220px;
    outline: none;
    transition: border-color 0.15s ease;
  }
  .search-box:focus {
    border-color: var(--border-strong);
  }

  /* Collapsible Sections */
  details.methodology-details {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
    margin-bottom: 0.75rem;
    overflow: hidden;
  }
  details.methodology-details summary {
    padding: 0.85rem 1.15rem;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.92rem;
    color: var(--text-primary);
    list-style: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
  }
  details.methodology-details summary::-webkit-details-marker { display: none; }
  details.methodology-details summary::after {
    content: "+";
    font-size: 1.1rem;
    color: var(--text-muted);
  }
  details.methodology-details[open] summary::after { content: "−"; }
  details.methodology-details[open] summary { border-bottom: 1px solid var(--border-subtle); }
  .details-body {
    padding: 1.15rem;
    font-size: 0.88rem;
    color: var(--text-secondary);
  }

  footer {
    border-top: 1px solid var(--border-default);
    padding-top: 1.75rem;
    margin-top: 3rem;
    text-align: center;
    font-size: 0.82rem;
    color: var(--text-muted);
  }

  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
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
    .header-actions, .filter-bar, .copy-btn, .search-box, nav.toc,
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
    details, details.finding-card-details, details.methodology-details {
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
    details summary .chevron, details summary::after {
      display: none !important;
    }
    details .finding-body, details .details-body {
      display: block !important;
    }
    .card, .item-card, .story-card, .score-card, .risk-bar-container, .defensive-section-box, .narrative-box, .sub-box, .notice-box {
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
    <div class="brand-tag">
      <span>FELIX SECURITY AUDITOR</span>
      <span>&bull;</span>
      <span>EXECUTIVE SECURITY DOSSIER</span>
    </div>
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

  <!-- 1. Report Header -->
  <header>
    <div class="header-title">
      <h1>FELIX SECURITY AUDIT REPORT</h1>
      <div class="header-meta">
        <span>Target: <strong>{{.Target}}</strong></span>
        <span>Generated: <strong>{{.Timestamp}}</strong></span>
        {{if .Duration}}<span>Duration: <strong>{{.Duration}}</strong></span>{{else if .DurationMs}}<span>Duration: <strong>{{.DurationMs}}ms</strong></span>{{end}}
        <span>Version: <strong>Felix {{.Version}}</strong></span>
      </div>
    </div>

    <!-- Precision Exposure Score Card -->
    <div class="score-card">
      <div class="score-card-lbl">EXPOSURE SCORE</div>
      <div class="score-card-row">
        {{if or (not .RiskScoreAvailable) (eq .CompletionStatus "BLOCKED") (eq .CompletionStatus "FAILED") (eq .RiskLevel "UNAVAILABLE")}}
        <div class="score-val" style="color: var(--crit);">N/A</div>
        <div class="score-verdict" style="color: var(--crit);">
          {{if eq .CompletionStatus "BLOCKED"}}BLOCKED{{else if eq .CompletionStatus "FAILED"}}FAILED{{else if or (eq .CompletionStatus "PARTIAL") (eq .CompletionStatus "INCOMPLETE")}}PARTIAL{{else}}UNAVAILABLE{{end}}
        </div>
        {{else}}
        <div class="score-val color-{{.RiskLevel}}">{{.RiskScore}}</div>
        <div class="score-denom">/ 100</div>
        <div class="score-verdict color-{{.RiskLevel}}">{{.RiskLevel}} RISK</div>
        {{end}}
      </div>
      <div class="score-meter-track">
        <div class="score-meter-fill risk-fill-{{.RiskLevel}}" style="width: {{if or (not .RiskScoreAvailable) (eq .CompletionStatus "BLOCKED") (eq .CompletionStatus "FAILED") (eq .RiskLevel "UNAVAILABLE")}}0%{{else}}{{.RiskScore}}%{{end}};"></div>
      </div>
    </div>
  </header>

  {{if eq .CompletionStatus "BLOCKED"}}
  <div style="background: var(--crit-bg); border: 1px solid var(--crit-border); border-radius: 3px; padding: 1.15rem 1.4rem; margin-bottom: 2rem; color: var(--crit);">
    <strong style="font-size: 1rem;">ASSESSMENT BLOCKED:</strong> Target presented access controls or automated challenge barriers (HTTP 403 / Cloudflare). In accordance with non-destructive authorized testing policies, automated assessments were halted. Security posture could not be evaluated.
  </div>
  {{else if eq .CompletionStatus "FAILED"}}
  <div style="background: var(--crit-bg); border: 1px solid var(--crit-border); border-radius: 3px; padding: 1.15rem 1.4rem; margin-bottom: 2rem; color: var(--crit);">
    <strong style="font-size: 1rem;">ASSESSMENT FAILED:</strong> Target reachability could not be established due to network, transport, or server errors. Security posture could not be evaluated.
  </div>
  {{else if or (eq .CompletionStatus "PARTIAL") (eq .CompletionStatus "INCOMPLETE")}}
  <div style="background: var(--high-bg); border: 1px solid var(--high-border); border-radius: 3px; padding: 1.15rem 1.4rem; margin-bottom: 2rem; color: var(--high);">
    <strong style="font-size: 1rem;">PARTIAL ASSESSMENT:</strong> Assessment was completed with partial target coverage or interrupted scopes. Unassessed components remain unevaluated.
  </div>
  {{end}}

  <!-- 2. Executive Summary -->
  <section>
    <h2>Executive Summary</h2>
    <div class="summary-narrative">
      <p>
        Felix {{if eq .CompletionStatus "BLOCKED"}}was blocked while assessing{{else if eq .CompletionStatus "FAILED"}}failed to connect to{{else if or (eq .CompletionStatus "PARTIAL") (eq .CompletionStatus "INCOMPLETE")}}conducted a partial defensive security audit of{{else}}completed an automated defensive security audit of{{end}} <strong>{{.Target}}</strong>.
        {{if eq .CompletionStatus "BLOCKED"}}
        The target denied access or presented an automated challenge barrier (HTTP 403 Forbidden). No challenge bypasses or invasive circumventions were attempted. Because the application was unreachable for analysis, no risk score was computed and its security posture remains unevaluated.
        {{else if eq .CompletionStatus "FAILED"}}
        Connection could not be established to the target due to network or transport errors. Because the target was unreachable, no risk score was computed and its security posture remains unevaluated.
        {{else if or (eq .CompletionStatus "PARTIAL") (eq .CompletionStatus "INCOMPLETE")}}
        Assessment was completed with partial coverage or interrupted scope boundaries. Unassessed components remain unevaluated and should not be assumed secure.
        {{else if eq .RiskScore 0}}
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

    {{if .HasCloudScope}}
    <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 0.5rem; padding: 1rem 1.25rem; margin-top: 1.25rem;">
      <div style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 0.6rem;">
        Cloud & Database Services Assessed & Scope Coverage
      </div>

      {{if .CloudServicesAssessed}}
      <div style="margin-bottom: 0.85rem;">
        <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.35rem;">Actively Assessed Services:</div>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;">
          {{range .CloudAssessedServicesDetails}}
          {{if .HasFindings}}
          <span class="badge badge-HIGH" style="font-size: 0.82rem; padding: 0.3rem 0.65rem;">{{.Name}} (Findings Detected)</span>
          {{else}}
          <span class="badge badge-INFO" style="font-size: 0.82rem; padding: 0.3rem 0.65rem;">{{.Name}} (0 Findings)</span>
          {{end}}
          {{end}}
        </div>
        <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.35rem;">
          Note: Zero detected findings in an actively assessed service indicates no evaluated vulnerabilities were observed during testing within the defined scope. It does not establish the complete absence of unassessed or internal risks.
        </div>
      </div>
      {{end}}

      {{if .CloudServicesDiscovered}}
      <div style="margin-bottom: 0.85rem;">
        <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Discovered Only (Passive / Unverified):</div>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;">
          {{range .CloudServicesDiscovered}}
          <span class="badge" style="background: var(--bg-elevated); border: 1px dashed var(--border-default); color: var(--text-secondary); font-size: 0.82rem; padding: 0.3rem 0.65rem;">{{.}} (Unverified)</span>
          {{end}}
        </div>
        <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.35rem;">
          These services were identified via static code references or connection indicators. Network accessibility, active credentials, and resource exposure remain unverified.
        </div>
      </div>
      {{end}}

      {{if .CloudServicesSkipped}}
      <div>
        <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Skipped / Out of Scope:</div>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;">
          {{range .CloudServicesSkipped}}
          <span class="badge" style="background: var(--bg-elevated); color: var(--text-muted); font-size: 0.82rem; padding: 0.3rem 0.65rem;">{{.}} (Skipped)</span>
          {{end}}
        </div>
      </div>
      {{end}}
    </div>
    {{end}}

    {{if .HasMobileScope}}
    <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 0.5rem; padding: 1.25rem; margin-top: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted);">
          Android APK Audit & Mobile Assessment Summary
        </div>
        <div>
          <span class="badge badge-INFO">{{.MobileAssessmentStatus}}</span>
          <span class="badge" style="background: var(--bg-elevated); color: var(--text-secondary); font-size: 0.8rem; margin-left: 0.35rem;">{{.MobileAnalysisMode}}</span>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; margin-bottom: 0.85rem; font-size: 0.85rem;">
        <div>
          <span style="color: var(--text-muted);">Package:</span>
          <div><strong><code>{{.MobilePackageName}}</code></strong></div>
        </div>
        <div>
          <span style="color: var(--text-muted);">Version:</span>
          <div><code>{{.MobileVersion}}</code></div>
        </div>
        <div>
          <span style="color: var(--text-muted);">SHA-256 Digest:</span>
          <div style="word-break: break-all;"><code style="font-size: 0.78rem;">{{.MobileSHA256}}</code></div>
        </div>
        <div>
          <span style="color: var(--text-muted);">SDK Compatibility:</span>
          <div><code>{{.MobileSDKInfo}}</code></div>
        </div>
      </div>

      {{if .MobileComponentSummary}}
      <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
        <strong>Component Scope:</strong> {{.MobileComponentSummary}}
      </div>
      {{end}}

      {{if not .HasMobileFindings}}
      <div style="background: var(--low-bg); border-left: 3px solid var(--low); padding: 0.65rem 0.85rem; border-radius: 0.25rem; font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.5rem;">
        <strong>Scope Notice:</strong> Zero security findings were identified during static APK analysis within the evaluated ruleset. Static analysis does not guarantee the absence of dynamic runtime vulnerabilities, business logic weaknesses, or server-side backend flaws.
      </div>
      {{end}}

      {{if .MobileLimitations}}
      <div style="margin-top: 0.75rem; padding-top: 0.5rem; border-top: 1px solid var(--border-subtle); font-size: 0.78rem; color: var(--text-muted);">
        <strong>Assessment Limitations:</strong>
        <ul style="padding-left: 1.25rem; margin-top: 0.25rem;">
          {{range .MobileLimitations}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
    {{end}}

    {{if .HasFrameworkScope}}
    <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 0.5rem; padding: 1.25rem; margin-top: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted);">
          Backend Frameworks & Runtime Assessment Summary
        </div>
        <div>
          <span class="badge badge-INFO">{{len .DetectedFrameworks}} Detected</span>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem; margin-bottom: 0.85rem;">
        {{range .DetectedFrameworks}}
        <div style="background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: 0.375rem; padding: 0.75rem 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
            <strong style="color: var(--text-primary); font-size: 0.95rem;">{{.Name}}</strong>
            {{if .Version}}<code style="font-size: 0.8rem; color: var(--low);">v{{.Version}}</code>{{end}}
          </div>
          <div style="margin-bottom: 0.4rem;">
            {{if eq .Status "VERIFIED_VULNERABILITY"}}
            <span class="badge badge-CRITICAL" style="font-size: 0.75rem;">{{.StatusText}}</span>
            {{else if eq .Status "CONFIGURATION_EXPOSURE"}}
            <span class="badge badge-MEDIUM" style="font-size: 0.75rem;">{{.StatusText}}</span>
            {{else if eq .Status "PROTECTED"}}
            <span class="badge badge-INFO" style="background: var(--verified-bg); color: var(--verified); border: 1px solid var(--verified-border); font-size: 0.75rem;">{{.StatusText}}</span>
            {{else if eq .Status "OBSERVED_SURFACE"}}
            <span class="badge badge-INFO" style="font-size: 0.75rem;">{{.StatusText}}</span>
            {{else}}
            <span class="badge badge-INFO" style="font-size: 0.75rem;">Clean (0 Findings)</span>
            {{end}}
          </div>
          <div style="font-size: 0.78rem; color: var(--text-muted); line-height: 1.4;">
            {{if gt .TotalFindings 0}}
              <span>Findings: <strong>{{.TotalFindings}}</strong> (Verified: {{.VerifiedCount}}, Detected: {{.DetectedCount}}, Observations: {{.ObservationCount}})</span>
            {{else}}
              <span>Zero vulnerabilities or configuration exposures detected in evaluated routes.</span>
            {{end}}
            {{if .Endpoints}}
            <div style="margin-top: 0.25rem; font-size: 0.75rem; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              Endpoints: {{range $i, $ep := .Endpoints}}{{if $i}}, {{end}}<code>{{$ep}}</code>{{end}}
            </div>
            {{end}}
          </div>
        </div>
        {{end}}
      </div>

      <div style="font-size: 0.78rem; color: var(--text-muted); line-height: 1.5; border-top: 1px solid var(--border-subtle); padding-top: 0.6rem; margin-top: 0.5rem;">
        <strong>Framework Assessment Policy:</strong> Identifying a backend framework or runtime header is an informational inventory observation and does NOT automatically constitute a security vulnerability. High and Critical severities are strictly reserved for verified exposures (such as unauthenticated debug modes, active execution profiling, or sensitive environment leaks).
      </div>
    </div>
    {{end}}

    {{if .ChangeSummary}}
    <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 0.5rem; padding: 1.25rem; margin-top: 1.25rem;">
      <div style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 0.6rem;">
        Security Posture Delta & Assessment History
      </div>
      <div style="font-size: 0.95rem; font-weight: 600; color: var(--text-primary); margin-bottom: 0.5rem;">
        {{.ChangeSummary.Headline}}
      </div>
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.85rem;">
        <span class="badge badge-HIGH" style="font-size: 0.8rem;">+{{.ChangeSummary.Counts.New}} New</span>
        <span class="badge badge-LOW" style="font-size: 0.8rem;">-{{.ChangeSummary.Counts.Resolved}} Resolved</span>
        <span class="badge" style="background: var(--bg-elevated); color: var(--text-secondary); font-size: 0.8rem;">{{.ChangeSummary.Counts.Persistent}} Persistent</span>
        {{if gt .ChangeSummary.Counts.SeverityIncreased 0}}<span class="badge badge-CRITICAL" style="font-size: 0.8rem;">▲ {{.ChangeSummary.Counts.SeverityIncreased}} Severity Increased</span>{{end}}
        {{if gt .ChangeSummary.Counts.SeverityDecreased 0}}<span class="badge badge-INFO" style="font-size: 0.8rem;">▼ {{.ChangeSummary.Counts.SeverityDecreased}} Severity Decreased</span>{{end}}
        {{if gt .ChangeSummary.Counts.Unknown 0}}<span class="badge badge-MEDIUM" style="font-size: 0.8rem;">? {{.ChangeSummary.Counts.Unknown}} Unverified</span>{{end}}
      </div>
      <div style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.5;">
        Baseline: <code>{{if .ChangeSummary.BaselineExecutionID}}{{.ChangeSummary.BaselineExecutionID}}{{else}}[Initial Assessment]{{end}}</code> |
        Comparison Status: <strong>{{.ChangeSummary.ComparisonStatus}}</strong>
        {{if not .ChangeSummary.IsReliable}} (Partial Coverage: {{.ChangeSummary.ReliabilityReason}}){{end}}
      </div>
    </div>
    {{end}}

    {{if not (or (eq .CompletionStatus "BLOCKED") (eq .CompletionStatus "FAILED") (eq .RiskLevel "UNAVAILABLE"))}}
    <!-- 3. Risk Meter -->
    <div class="risk-bar-container" style="margin-top: 1.5rem;">
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
      {{if .CommercialReport}}
      {{if .CommercialReport.RiskOverview.ScoreBreakdown.Formula}}
      <div style="margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid var(--border-subtle);">
        <div style="font-size: 0.82rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.35rem;">Score Attribution & Reconciliation:</div>
        <code style="font-size: 0.82rem; color: var(--low);">{{.CommercialReport.RiskOverview.ScoreBreakdown.Formula}}</code>
      </div>
      {{if .CommercialReport.RiskOverview.FindingRiskContributions}}
      <table class="data-table">
        <thead>
          <tr>
            <th>Ref</th>
            <th>Title</th>
            <th>Type</th>
            <th>Status</th>
            <th>Severity</th>
            <th style="text-align: right;">Raw</th>
            <th style="text-align: right;">Weight</th>
            <th style="text-align: right;">Adjusted</th>
          </tr>
        </thead>
        <tbody>
          {{range .CommercialReport.RiskOverview.FindingRiskContributions}}
          <tr>
            <td><code>{{.FindingID}}</code></td>
            <td>{{.Title}}</td>
            <td><span class="badge badge-INFO">{{.RiskType}}</span></td>
            <td><span class="badge badge-{{.VerificationStatus}}">{{.VerificationStatus}}</span></td>
            <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
            <td style="text-align: right;">{{.Score}}</td>
            <td style="text-align: right; color: var(--text-muted);">{{printf "%.1fx" .Weight}}</td>
            <td style="text-align: right; font-weight: 700; color: var(--verified);">{{printf "%.2f" .AdjustedScore}} pts</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}
      {{end}}
      {{end}}
    </div>
    {{end}}

    <!-- 4. Findings & Verification Breakdown Grid -->
    <div class="grid">
      <div class="card">
        <div class="card-lbl">Total Findings</div>
        <div class="card-val">{{.Summary.TotalFindings}}</div>
      </div>
      <div class="card card-crit">
        <div class="card-lbl">Critical</div>
        <div class="card-val color-CRITICAL">{{.Summary.CriticalCount}}</div>
      </div>
      <div class="card card-high">
        <div class="card-lbl">High</div>
        <div class="card-val color-HIGH">{{.Summary.HighCount}}</div>
      </div>
      <div class="card card-med">
        <div class="card-lbl">Medium</div>
        <div class="card-val color-MEDIUM">{{.Summary.MediumCount}}</div>
      </div>
      <div class="card card-low">
        <div class="card-lbl">Low & Info</div>
        <div class="card-val color-LOW">{{add .Summary.LowCount .Summary.InfoCount}}</div>
      </div>
    </div>

    <h3>Verification Breakdown</h3>
    <div class="grid">
      <div class="card">
        <div class="card-lbl">Verified Exposures</div>
        <div class="card-val" style="color: var(--verified);">{{.Summary.VerifiedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Detected Candidates</div>
        <div class="card-val" style="color: var(--med);">{{.Summary.DetectedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Observed Inventory</div>
        <div class="card-val" style="color: var(--low);">{{.Summary.ObservedCount}}</div>
      </div>
      <div class="card">
        <div class="card-lbl">Defended / Protected</div>
        <div class="card-val" style="color: var(--defended);">{{.Summary.NotExposedCount}}</div>
      </div>
    </div>
  </section>

  <!-- 3. Dedicated Defensive Boundaries & Verified Controls Section -->
  <section>
    <h2>Defensive Boundaries & Verified Controls</h2>
    <div class="defensive-section-box">
      <div class="defensive-header">
        <div class="defensive-title">Verified In-Place Defenses & Access Restrictions</div>
        <div class="defensive-badge">{{.Summary.NotExposedCount}} Active Defensive Controls</div>
      </div>
      <div class="defensive-desc">
        The following security boundaries were actively evaluated and verified to enforce safe configurations, public access denial, or authorization boundaries. FELIX tests positive defensive assertions without conflating absence of evidence with evidence of defense.
      </div>

      {{if gt .Summary.NotExposedCount 0}}
      <div class="table-wrapper">
      <table class="data-table">
        <thead>
          <tr>
            <th>Control ID / Check</th>
            <th>Asset / Location</th>
            <th>Verification Result</th>
            <th>Defensive Evidence</th>
          </tr>
        </thead>
        <tbody>
          {{range .Findings}}
          {{if or (eq .Verification.Status "NOT_EXPOSED") (eq .Status "DEFENDED") (ne .EvidenceDetails.NegativeEvidence "")}}
          <tr>
            <td><code>{{.ID}}</code> — {{.Title}}</td>
            <td><code>{{if .EvidenceDetails.Location}}{{.EvidenceDetails.Location}}{{else}}{{.Endpoint}}{{end}}</code></td>
            <td><span class="badge badge-NOT_EXPOSED">DEFENDED</span></td>
            <td>{{if .EvidenceDetails.NegativeEvidence}}{{.EvidenceDetails.NegativeEvidence}}{{else}}{{.Verification.Result}}{{end}}</td>
          </tr>
          {{end}}
          {{end}}
        </tbody>
      </table>
      </div>
      {{else}}
      <div style="background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: 0.375rem; padding: 1rem; color: var(--text-muted); font-size: 0.88rem;">
        No explicit non-exposed defensive records were registered during this assessment. This indicates that evaluated targets either did not exhibit negative control markers or that assessed services operated without detectable boundary defenses.
      </div>
      {{end}}

      <div style="margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid var(--border-subtle); font-size: 0.78rem; color: var(--text-muted); line-height: 1.5;">
        <strong>Defensive Boundary Verification Standard:</strong> A verified defensive control confirms that an active security probe was safely rejected or access was properly denied (e.g. HTTP 401/403 or blocked query). It does not claim full infrastructure invulnerability beyond tested endpoints.
      </div>
    </div>
  </section>

  <!-- 4. Investigate First -->
  {{if .TopPriorities}}
  <section>
    <h2>Investigate First (Actionable Priorities)</h2>
    {{range .TopPriorities}}
    <div class="item-card">
      <div class="item-header">
        <div class="item-title">{{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
          <span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span>
          <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
          {{if .Status}}<span class="badge badge-{{.Status}}">{{.Status}}</span>{{end}}
          {{if .AnalysisMethod}}<span class="badge badge-{{.AnalysisMethod}}">{{.AnalysisMethod}}</span>{{end}}
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
        {{if .Verification.PolicyID}}<span style="font-size:0.8rem; color:var(--low); margin-left:0.5rem;">[{{.Verification.PolicyID}}]</span>{{end}}
      </div>
      {{end}}

      {{if .Verification.SafeCurlCommand}}
      <div style="margin-bottom: 0.85rem;">
        <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Safe Reproduction:</span>
        <div class="code-snippet" style="margin-top: 0.25rem;">{{.Verification.SafeCurlCommand}}</div>
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

  <!-- 5. Correlated Security Stories -->
  {{if .SecurityStories}}
  <section>
    <h2>Correlated Security Stories ({{len .SecurityStories}})</h2>
    {{range .SecurityStories}}
    <div class="story-card">
      <div class="item-header">
        <div class="item-title">{{.Title}}</div>
        <div style="display: flex; gap: 0.4rem; align-items: center;">
          {{if .RiskContribution}}<span class="badge badge-INFO">+{{.RiskContribution}} Risk Pts</span>{{end}}
          <span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span>
        </div>
      </div>
      {{if .Summary}}
      <p style="margin-bottom: 0.5rem; font-size: 0.95rem; font-weight: 600; color: var(--text-primary);">{{.Summary}}</p>
      {{end}}
      <p style="margin-bottom: 0.75rem; font-size: 0.9rem; color: var(--text-secondary);">{{.Description}}</p>

      <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem;">Correlated Signals & Evidence:</div>
      <ul class="story-list">
        {{range .Evidence}}
        <li>{{.}}</li>
        {{end}}
      </ul>

      <div style="font-size: 0.85rem; font-weight: 600; color: var(--crit); margin-bottom: 0.25rem;">Security Impact:</div>
      <p style="font-size: 0.9rem; margin-bottom: 0.85rem; color: var(--text-secondary);">{{.Impact}}</p>

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

  <!-- 6. Correlated Attack Paths -->
  <section id="attack-paths-section">
    {{if not .AttackPaths}}
    <h2>Correlated Attack Paths (0)</h2>
    <div class="empty-graph-card">
      <div class="empty-graph-title">No Evidence-Supported Multi-Hop Attack Paths Detected</div>
      <p class="empty-graph-desc">
        Correlation analysis evaluated findings across the target boundary. No multi-hop exploit sequences (3+ hops) or causal transition chains met the empirical verification threshold for evidence-supported chaining.
      </p>
      <div class="empty-graph-meta">Individual component findings remain actionable in the detailed inventory below.</div>
    </div>
    {{else}}
    <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
      <h2 style="margin-bottom: 0;">Correlated Attack Paths ({{len .AttackPaths}})</h2>
      <div style="font-size: 0.82rem; color: var(--text-muted);">Evidence-backed exploit chains synthesizing multiple vulnerabilities</div>
    </div>

    {{if gt (len .AttackPaths) 1}}
    <!-- Path Selector Tabs -->
    <div class="path-selector-tabs" role="tablist" aria-label="Select Attack Path">
      {{range $i, $p := .AttackPaths}}
      <button class="path-tab-btn {{if eq $i 0}}active{{end}}" role="tab" aria-selected="{{if eq $i 0}}true{{else}}false{{end}}" onclick="switchAttackPath({{$i}})">
        Path {{$i | add1}}: {{$p.Title}}
      </button>
      {{end}}
    </div>
    {{end}}

    {{range $idx, $p := .AttackPaths}}
    <div id="path-view-{{$idx}}" class="path-view-wrapper {{if ne $idx 0}}hidden-path{{end}}" data-path-id="{{$p.ID}}">
      <!-- Hidden template containing pre-generated safe bash reproduction script -->
      <template id="reproduce-script-{{$p.ID}}">{{renderReproductionScript $p $.Findings}}</template>
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

      <!-- Preserved Story Narrative & Fallback Card -->
      <div class="story-card" style="border-left-color: {{if eq $p.Status "VERIFIED"}}var(--verified){{else if eq $p.Status "CANDIDATE"}}var(--med){{else}}var(--info){{end}};">
        <div class="item-header">
          <div class="item-title">{{if $p.SyntheticFixture}}<span class="badge badge-INFO">[SYNTHETIC FIXTURE]</span> {{end}}{{$p.Title}}</div>
          <div style="display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap;">
            <span class="badge badge-{{$p.Status}}">{{$p.Status}}</span>
            <span class="badge badge-{{$p.CombinedRiskLevel}}">{{severityBadge $p.CombinedRiskLevel}} ({{$p.CombinedRiskScore}}/100)</span>
            <span class="badge badge-INFO">Conf: {{$p.Confidence}}</span>
          </div>
        </div>

        <!-- Inline Visual Attack Flow -->
        <div class="attack-flow-diagram">
          <div class="flow-node">
            <div class="flow-node-badge">ENTRY POINT</div>
            <div class="flow-node-title">{{if $p.EntryPoint}}{{$p.EntryPoint}}{{else}}Public Surface{{end}}</div>
          </div>
          <div class="flow-arrow" aria-hidden="true"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg></div>
          <div class="flow-node">
            <div class="flow-node-badge">PRIMARY WEAKNESS</div>
            <div class="flow-node-title">{{$p.PrimaryWeakness}}</div>
          </div>
          <div class="flow-arrow" aria-hidden="true"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg></div>
          <div class="flow-node">
            <div class="flow-node-badge">TARGET ASSET</div>
            <div class="flow-node-title">{{$p.TargetAsset}}</div>
          </div>
        </div>

        <div class="item-meta">
          <strong>Target Asset:</strong> {{$p.TargetAsset}}
          {{if $p.EntryPoint}}&bull; <strong>Entry Point:</strong> {{$p.EntryPoint}}{{end}}
          &bull; <strong>Primary Weakness:</strong> {{$p.PrimaryWeakness}}
        </div>

        <div style="font-size: 0.85rem; font-weight: 600; color: var(--crit); margin-bottom: 0.25rem;">Terminal Impact:</div>
        <p style="font-size: 0.9rem; margin-bottom: 0.75rem; color: var(--text-secondary);">{{$p.TerminalImpact}}</p>

        {{if $p.RiskRationale}}
        <p style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 0.75rem;"><strong>Risk Rationale:</strong> {{$p.RiskRationale}}</p>
        {{end}}

        {{if $p.Transitions}}
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem;">Validated Transition Sequence:</div>
        <ul class="story-list">
          {{range $p.Transitions}}
          <li>{{.}}</li>
          {{end}}
        </ul>
        {{end}}

        {{if $p.Assumptions}}
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--med); margin-bottom: 0.25rem;">Preconditions & Assumptions:</div>
        <ul class="story-list">
          {{range $p.Assumptions}}
          <li>{{.}}</li>
          {{end}}
        </ul>
        {{end}}

        {{if $p.MissingEvidence}}
        <div class="negative-block" style="margin-bottom: 0.75rem;">
          <strong>Missing Evidence / Verification Gaps:</strong>
          <ul style="padding-left: 1.25rem; margin-top: 0.25rem;">
            {{range $p.MissingEvidence}}
            <li>{{.}}</li>
            {{end}}
          </ul>
        </div>
        {{end}}

        {{if $p.Remediation}}
        <div class="remediation-block">
          <strong>Choke Point Remediation:</strong> {{$p.Remediation}}
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
    {{end}}
  </section>

  {{if .Reconciliation}}
  <!-- Shadow API Surface & Topology Reconciliation (P14.2) -->
  <section id="shadow-api-section" style="margin-top: 2rem; margin-bottom: 2rem;">
    <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
      <h2 style="margin-bottom: 0;">Shadow API Surface &amp; Topology Reconciliation ({{len .Reconciliation.ShadowSurface}})</h2>
      <div style="font-size: 0.82rem; color: var(--text-muted);">Reconciling client-discovered route candidates against declared API specifications</div>
    </div>

    <!-- Summary Metrics Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.25rem;">
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{{.Reconciliation.TotalDiscoveredCandidates}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Discovered Routes</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{{.Reconciliation.TotalDocumentedOperations}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Documented Ops</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--low);">{{.Reconciliation.TotalDocumentedMatches}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Verified Matches</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--high);">{{.Reconciliation.TotalUndocumentedCandidates}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Undocumented Routes</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--crit);">{{.Reconciliation.TotalSensitiveShadowRoutes}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Sensitive Boundaries</div>
      </div>
    </div>

    {{if .Reconciliation.ShadowSurface}}
    <!-- Shadow Surface Table -->
    <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border-card); background: rgba(255,255,255,0.02); color: var(--text-muted);">
            <th style="padding: 0.75rem 1rem;">Priority</th>
            <th style="padding: 0.75rem 1rem;">Method</th>
            <th style="padding: 0.75rem 1rem;">Canonical Route</th>
            <th style="padding: 0.75rem 1rem;">Sensitive Identifiers</th>
            <th style="padding: 0.75rem 1rem;">Discovery Source</th>
            <th style="padding: 0.75rem 1rem;">Match Rationale</th>
          </tr>
        </thead>
        <tbody>
          {{range .Reconciliation.ShadowSurface}}
          <tr style="border-bottom: 1px solid var(--border-card);">
            <td style="padding: 0.75rem 1rem; white-space: nowrap;">
              <span class="badge" style="font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px;
                {{if eq .Priority "CRITICAL_SHADOW"}}background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444;
                {{else if eq .Priority "HIGH_PRIORITY_SHADOW"}}background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316;
                {{else if eq .Priority "STANDARD_SHADOW"}}background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308;
                {{else}}background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #64748b;{{end}}">
                {{.Priority}}
              </span>
            </td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; font-weight: 600;">{{.Method}}</td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; color: var(--text-primary);">{{.CanonicalPath}}</td>
            <td style="padding: 0.75rem 1rem;">
              {{if .SensitiveHits}}
                {{range .SensitiveHits}}
                <span style="display: inline-block; background: rgba(239, 68, 68, 0.15); color: #f87171; font-size: 0.72rem; padding: 0.15rem 0.4rem; border-radius: 3px; margin: 0.1rem;">
                  {{.Type}} ({{.Location}})
                </span>
                {{end}}
              {{else}}
                <span style="color: var(--text-muted);">&mdash;</span>
              {{end}}
            </td>
            <td style="padding: 0.75rem 1rem; color: var(--text-muted); font-size: 0.8rem;">{{.DiscoverySource}}</td>
            <td style="padding: 0.75rem 1rem; color: var(--text-secondary); font-size: 0.82rem;">{{.MatchRationale}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{end}}
  </section>
  {{end}}

  {{if .ProberResults}}
  <!-- Live Exploitability & Reachability Prober (P14.3) -->
  <section id="prober-section" style="margin-top: 2rem; margin-bottom: 2rem;">
    <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
      <h2 style="margin-bottom: 0;">Live Exploitability &amp; Reachability Prober ({{.ProberResults.TotalProbesAttempted}})</h2>
      <div style="font-size: 0.82rem; color: var(--text-muted);">Scope-enforced non-destructive live HTTP probe validation</div>
    </div>

    <!-- Summary Metrics Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.25rem;">
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{{.ProberResults.TotalCandidatesEvaluated}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Evaluated</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--low);">{{.ProberResults.TotalReachable}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Reachable</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: #38bdf8;">{{.ProberResults.TotalReachableWithMetadata}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">With Metadata</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--high);">{{.ProberResults.TotalAuthenticationRequired}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Auth Enforced</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-muted);">{{.ProberResults.TotalNotFound}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Not Found</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: #fbbf24;">{{.ProberResults.TotalInconclusive}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Inconclusive</div>
      </div>
    </div>

    {{if .ProberResults.Results}}
    <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border-card); background: rgba(255,255,255,0.02); color: var(--text-muted);">
            <th style="padding: 0.75rem 1rem;">Classification</th>
            <th style="padding: 0.75rem 1rem;">Probe</th>
            <th style="padding: 0.75rem 1rem;">Status</th>
            <th style="padding: 0.75rem 1rem;">Endpoint</th>
            <th style="padding: 0.75rem 1rem;">Evidence &amp; Rationale</th>
          </tr>
        </thead>
        <tbody>
          {{range .ProberResults.Results}}
          <tr style="border-bottom: 1px solid var(--border-card);">
            <td style="padding: 0.75rem 1rem; white-space: nowrap;">
              <span class="badge" style="font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px;
                {{if or (eq .Classification "REACHABLE") (eq .Classification "REACHABLE_WITH_METADATA")}}background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e;
                {{else if or (eq .Classification "AUTHENTICATION_REQUIRED") (eq .Classification "AUTHORIZATION_BOUNDARY_OBSERVED")}}background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316;
                {{else if eq .Classification "INCONCLUSIVE"}}background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308;
                {{else}}background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #64748b;{{end}}">
                {{.Classification}}
              </span>
            </td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; font-weight: 600;">{{.ProbeMethod}}</td>
            <td style="padding: 0.75rem 1rem; font-family: monospace;">{{if gt .StatusCode 0}}{{.StatusCode}}{{else}}&mdash;{{end}}</td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; color: var(--text-primary);">{{.CanonicalPath}}</td>
            <td style="padding: 0.75rem 1rem; color: var(--text-secondary); font-size: 0.82rem;">
              {{.Rationale}}
              {{if .StructuredMetadataType}}<div style="font-size: 0.75rem; color: #38bdf8; margin-top: 0.2rem;">Metadata: {{.StructuredMetadataType}}</div>{{end}}
              {{if .RedirectInfo}}<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem;">Redirect: {{.RedirectInfo.RedirectURL}} (In-Scope: {{.RedirectInfo.IsInScope}})</div>{{end}}
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{end}}
  </section>
  {{end}}

  {{if .CrossTenantResults}}
  <!-- Declarative Multi-Tenant & Cross-Tenant Authorization Checks (P14.4) -->
  <section id="cross-tenant-section" style="margin-top: 2rem; margin-bottom: 2rem;">
    <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
      <h2 style="margin-bottom: 0;">Multi-Tenant Isolation &amp; Cross-Tenant Authorization ({{.CrossTenantResults.TotalExecuted}})</h2>
      <div style="font-size: 0.82rem; color: var(--text-muted);">Declarative dual opt-in cross-tenant authorization and BOLA/IDOR boundary testing</div>
    </div>

    <!-- Summary Metrics Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.25rem;">
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{{.CrossTenantResults.TotalComparisonsConfigured}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Configured</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{{.CrossTenantResults.TotalExecuted}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Executed</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--crit);">{{.CrossTenantResults.TotalCrossTenantAccessObserved}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">BOLA Observed</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--low);">{{.CrossTenantResults.TotalAccessDeniedObserved}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Access Denied (403)</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-muted);">{{.CrossTenantResults.TotalNotFoundObserved}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Not Found (404)</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: #fbbf24;">{{.CrossTenantResults.TotalInconclusive}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Inconclusive</div>
      </div>
      <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 1rem; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-muted);">{{.CrossTenantResults.TotalSkipped}}</div>
        <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem;">Skipped</div>
      </div>
    </div>

    {{if .CrossTenantResults.Warnings}}
    <div style="background: var(--bg-card); border-left: 3px solid #fbbf24; padding: 0.65rem 0.85rem; border-radius: 0.25rem; font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 1rem;">
      <strong>Policy Notice:</strong>
      <ul style="padding-left: 1.25rem; margin-top: 0.25rem; margin-bottom: 0;">
        {{range .CrossTenantResults.Warnings}}
        <li>{{.}}</li>
        {{end}}
      </ul>
    </div>
    {{end}}

    {{if .CrossTenantResults.Results}}
    <div style="background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border-card); background: rgba(255,255,255,0.02); color: var(--text-muted);">
            <th style="padding: 0.75rem 1rem;">Comparison ID</th>
            <th style="padding: 0.75rem 1rem;">Classification</th>
            <th style="padding: 0.75rem 1rem;">Requester &rarr; Owner</th>
            <th style="padding: 0.75rem 1rem;">Resource ID</th>
            <th style="padding: 0.75rem 1rem;">HTTP Status</th>
            <th style="padding: 0.75rem 1rem;">Evidence &amp; Rationale</th>
          </tr>
        </thead>
        <tbody>
          {{range .CrossTenantResults.Results}}
          <tr style="border-bottom: 1px solid var(--border-card);">
            <td style="padding: 0.75rem 1rem; font-family: monospace; font-size: 0.78rem;">{{.ComparisonID}}</td>
            <td style="padding: 0.75rem 1rem; white-space: nowrap;">
              <span class="badge" style="font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px;
                {{if .IsBOLAObserved}}background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444;
                {{else if eq .Classification "ACCESS_DENIED_OBSERVED"}}background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e;
                {{else if eq .Classification "NOT_FOUND_OBSERVED"}}background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #64748b;
                {{else if eq .Classification "AUTHENTICATION_REQUIRED"}}background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316;
                {{else if eq .Classification "INCONCLUSIVE"}}background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308;
                {{else}}background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #64748b;{{end}}">
                {{if .IsBOLAObserved}}BOLA OBSERVED{{else}}{{.Classification}}{{end}}
              </span>
            </td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; font-size: 0.8rem;">
              <strong>{{.RequesterTenant}}</strong> &rarr; {{.ResourceOwnerTenant}}
            </td>
            <td style="padding: 0.75rem 1rem; font-family: monospace; font-size: 0.8rem; color: var(--text-primary);">{{.ResourceID}}</td>
            <td style="padding: 0.75rem 1rem; font-family: monospace;">{{if gt .StatusCode 0}}{{.StatusCode}}{{else}}&mdash;{{end}}</td>
            <td style="padding: 0.75rem 1rem; color: var(--text-secondary); font-size: 0.82rem;">
              {{.Rationale}}
              {{if .EvidenceSnippet}}<div style="font-size: 0.75rem; font-family: monospace; color: var(--text-muted); margin-top: 0.2rem; background: rgba(0,0,0,0.2); padding: 0.25rem 0.5rem; border-radius: 3px;">{{.EvidenceSnippet}}</div>{{end}}
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
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
      <button class="filter-btn" onclick="filterFindings('CLOUD')">Cloud & DB</button>
      {{if .HasMobileScope}}<button class="filter-btn" onclick="filterFindings('MOBILE')">Mobile & APK</button>{{end}}
      {{if .HasFrameworkScope}}<button class="filter-btn" onclick="filterFindings('FRAMEWORK')">Frameworks</button>{{end}}
      <input type="text" class="search-box" id="findingSearch" placeholder="Search findings..." onkeyup="searchFindings()">
    </div>

    <div id="findingsContainer">
      {{if not .Findings}}
      <div class="card" style="text-align: center; padding: 2.5rem; color: var(--text-secondary);">
        No security findings detected on this target.
      </div>
      {{end}}

      {{range .Findings}}
      <details class="finding-card-details finding-item" id="finding-{{.ID}}" data-severity="{{.Severity}}" data-verification="{{.Verification.Status}}" data-source="{{.Source}}" data-category="{{.Category}}" data-framework="{{.Framework}}">
        <summary class="finding-summary-row">
          <div class="finding-header-left">
            <span class="badge badge-{{.Severity}}">{{severityBadge .Severity}}</span>
            <span class="item-title">[{{.ID}}] {{.Title}}</span>
          </div>
          <div class="finding-header-right">
            <span class="badge badge-INFO">Conf: {{.Confidence}}</span>
            {{if .Status}}<span class="badge badge-{{.Status}}">{{.Status}}</span>{{end}}
            {{if .Verification.Status}}
            <span class="badge badge-{{.Verification.Status}}">{{.Verification.Status}}</span>
            {{end}}
            {{if and .Framework (ne .Framework "generic")}}
            <span class="badge" style="background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border);">{{.Framework}}{{if .FrameworkVersion}} v{{.FrameworkVersion}}{{end}}</span>
            {{end}}
            <span class="chevron" aria-hidden="true"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></span>
          </div>
        </summary>

        <div class="finding-body">
          <div class="item-meta">
            <strong>Location:</strong> {{if .EvidenceDetails.Location}}{{.EvidenceDetails.Location}}{{else}}{{.Endpoint}}{{end}} ({{.Method}})
            &bull; <strong>Detection:</strong> {{if .EvidenceDetails.DetectionMethod}}{{.EvidenceDetails.DetectionMethod}}{{else}}{{.Source}}{{end}}
            &bull; <strong>Category:</strong> {{.Category}}
            {{if and .Framework (ne .Framework "generic")}}&bull; <strong>Framework:</strong> {{.Framework}}{{if .FrameworkVersion}} (v{{.FrameworkVersion}}){{end}}{{end}}
            {{if .EvidenceDetails.Details}}
              {{if .EvidenceDetails.Details.technology}}&bull; <strong>Service:</strong> {{.EvidenceDetails.Details.technology}} ({{.EvidenceDetails.Details.family}}){{end}}
              {{if .EvidenceDetails.Details.resource_scope}}&bull; <strong>Resource:</strong> {{.EvidenceDetails.Details.resource_scope}}{{end}}
              {{if .EvidenceDetails.Details.auth_context}}&bull; <strong>Auth:</strong> {{.EvidenceDetails.Details.auth_context}}{{end}}
              {{if .EvidenceDetails.Details.package_name}}&bull; <strong>Package:</strong> {{.EvidenceDetails.Details.package_name}}{{end}}
              {{if .EvidenceDetails.Details.component_name}}&bull; <strong>Component:</strong> {{.EvidenceDetails.Details.component_name}}{{end}}
              {{if .EvidenceDetails.Details.resolved_name}}&bull; <strong>Component:</strong> {{.EvidenceDetails.Details.resolved_name}}{{end}}
              {{if .EvidenceDetails.Details.permission}}&bull; <strong>Permission:</strong> {{.EvidenceDetails.Details.permission}}{{end}}
            {{end}}
          </div>
          <div class="item-desc">{{.Description}}</div>

          {{if .Verification.Result}}
          <div class="verification-block">
            <strong>Verification Status ({{.Verification.Status}}):</strong> {{.Verification.Result}}
            {{if .Verification.PolicyID}}<span style="font-size:0.8rem; color:var(--low); margin-left:0.5rem;">[{{.Verification.PolicyID}}]</span>{{end}}
          </div>
          {{end}}

          {{if .Verification.SafeCurlCommand}}
          <div style="margin-bottom: 0.85rem;">
            <div class="evidence-header-row">
              <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Safe Reproduction:</span>
              <button class="copy-btn" onclick="copyEvidence(this, 'curl-{{.ID}}')">Copy Command</button>
            </div>
            <div class="code-snippet" id="curl-{{.ID}}" style="margin-top: 0.25rem;">{{.Verification.SafeCurlCommand}}</div>
          </div>
          {{end}}

          {{if .Evidence}}
          <div style="margin-bottom: 0.85rem;">
            <div class="evidence-header-row">
              <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Sanitized Evidence:</span>
              <button class="copy-btn" onclick="copyEvidence(this, 'ev-{{.ID}}')">Copy Evidence</button>
            </div>
            <div class="code-snippet" id="ev-{{.ID}}">{{.Evidence}}</div>
          </div>
          {{end}}

          {{if .EvidenceDetails.NegativeEvidence}}
          <div class="negative-block negative-evidence-box">
            <strong>Negative Evidence / Safety Verification:</strong> {{.EvidenceDetails.NegativeEvidence}}
          </div>
          {{end}}

          {{if .RemediationAdvice}}
          <div class="remediation-block" style="margin-bottom: 0.75rem;">
            <strong>Remediation Summary:</strong> {{.RemediationAdvice.Summary}}
            {{if .RemediationAdvice.Steps}}
            <ul style="padding-left: 1.25rem; margin-top: 0.35rem;">
              {{range .RemediationAdvice.Steps}}
              <li>{{.}}</li>
              {{end}}
            </ul>
            {{end}}
            {{if .RemediationAdvice.CodeSnippet}}
            <div class="code-snippet" style="margin-top: 0.5rem; background: var(--bg-surface);">{{.RemediationAdvice.CodeSnippet}}</div>
            {{end}}
          </div>
          {{else if .Remediation}}
          <div class="remediation-block">
            <strong>Remediation:</strong> {{.Remediation}}
          </div>
          {{end}}
        </div>
      </details>
      {{end}}
    </div>
  </section>

  <!-- 8. Technical Details & Scope -->
  <section>
    <h2>Assessment Methodology & Technical Scope</h2>

    <details class="methodology-details">
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

    <details class="methodology-details">
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

    <details class="methodology-details">
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

  function filterFindings(sev) {
    document.querySelectorAll('.filter-btn').forEach(function(btn) { btn.classList.remove('active'); });
    if (window.event && window.event.target) {
      window.event.target.classList.add('active');
    }

    var items = document.querySelectorAll('.finding-item');
    items.forEach(function(item) {
      if (sev === 'all') {
        item.style.display = 'block';
      } else if (sev === 'VERIFIED') {
        item.style.display = item.getAttribute('data-verification') === 'VERIFIED' ? 'block' : 'none';
      } else if (sev === 'CLOUD') {
        var src = (item.getAttribute('data-source') || '').toLowerCase();
        var cat = (item.getAttribute('data-category') || '').toLowerCase();
        item.style.display = (src === 'cloud' || cat.indexOf('cloud') !== -1 || cat.indexOf('database') !== -1 || cat.indexOf('storage') !== -1 || cat.indexOf('indicator') !== -1) ? 'block' : 'none';
      } else if (sev === 'MOBILE') {
        var srcM = (item.getAttribute('data-source') || '').toLowerCase();
        var catM = (item.getAttribute('data-category') || '').toLowerCase();
        item.style.display = (srcM === 'apk' || srcM === 'mobile' || catM.indexOf('android') !== -1 || catM.indexOf('apk') !== -1) ? 'block' : 'none';
      } else if (sev === 'FRAMEWORK') {
        var fw = (item.getAttribute('data-framework') || '').toLowerCase();
        var catF = (item.getAttribute('data-category') || '').toLowerCase();
        item.style.display = (fw !== '' && fw !== 'generic' || catF.indexOf('actuator') !== -1 || catF.indexOf('django') !== -1 || catF.indexOf('fastapi') !== -1 || catF.indexOf('laravel') !== -1 || catF.indexOf('ignition') !== -1 || catF.indexOf('telescope') !== -1 || catF.indexOf('node') !== -1 || catF.indexOf('go-') !== -1 || catF.indexOf('golang') !== -1 || catF.indexOf('pprof') !== -1 || catF.indexOf('vars') !== -1) ? 'block' : 'none';
      } else {
        item.style.display = item.getAttribute('data-severity') === sev ? 'block' : 'none';
      }
    });
  }

  function searchFindings() {
    var query = document.getElementById('findingSearch').value.toLowerCase();
    var items = document.querySelectorAll('.finding-item');
    items.forEach(function(item) {
      var text = (item.innerText || item.textContent).toLowerCase();
      item.style.display = text.indexOf(query) !== -1 ? 'block' : 'none';
    });
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

// GenerateHTML renders the sanitized audit report into a standalone, offline HTML document.
func GenerateHTML(rep Report) (string, error) {
	sanitized := SanitizeReport(rep)
	for i := range sanitized.AttackPaths {
		if len(sanitized.AttackPaths[i].GraphNodes) == 0 {
			EnrichAttackPathGraph(&sanitized.AttackPaths[i], sanitized.Findings)
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
		"renderReproductionScript": func(path AttackPathSummary, findings []Finding) string {
			plan, err := GenerateReproductionScript(path, findings, ReproductionOptions{})
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

// WriteHTML writes the self-contained HTML report to disk with restricted permissions (0600).
func WriteHTML(rep Report, filePath string) error {
	content, err := GenerateHTML(rep)
	if err != nil {
		return err
	}
	return writeReportFileSafely(filePath, []byte(content))
}
