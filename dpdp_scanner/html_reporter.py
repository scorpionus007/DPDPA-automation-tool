from __future__ import annotations

import html
import json
import os
from typing import Dict, List, Optional


def _safe(text: object) -> str:
    return html.escape("" if text is None else str(text))


def generate_html_report(
    findings: List[Dict],
    output: str,
    repo_name: str = "Repository",
    compliance_score: Optional[Dict] = None,
    delta: Optional[Dict] = None,
    repo_url: str = "",
    commit_hash: str = "",
) -> str:
    if not output.endswith(".html"):
        output = f"{output}.html"
    out_dir = os.path.dirname(output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    findings_json = json.dumps(findings)
    score = (compliance_score or {}).get("score", "N/A")
    grade = (compliance_score or {}).get("grade", "")
    new_keys = set()
    if delta and not delta.get("is_first_scan"):
        new_keys = {
            f"{item.get('rule','')}::{item.get('file','')}::{item.get('description','')[:80]}"
            for item in delta.get("new_findings", [])
        }

    cards = []
    for finding in findings:
        key = f"{finding.get('rule','')}::{finding.get('file','')}::{str(finding.get('description',''))[:80]}"
        is_new = key in new_keys
        file_path = str(finding.get("file", "N/A"))
        github_link = ""
        if repo_url.startswith("https://github.com/") and file_path not in {"", "N/A", "MULTIPLE", "REPO-WIDE"}:
            ref = commit_hash or "HEAD"
            github_link = f"{repo_url.rstrip('/')}/blob/{ref}/{file_path}"
        cards.append(
            f"""
            <article class="card" data-severity="{_safe(finding.get('severity',''))}" data-section="{_safe(finding.get('dpdp_section',''))}">
              <div class="meta">
                <span class="sev">{_safe(finding.get('severity',''))}</span>
                <span>{_safe(finding.get('dpdp_section',''))}</span>
                {'<span class="new">NEW</span>' if is_new else ''}
              </div>
              <h3>{_safe(finding.get('rule',''))}</h3>
              <p class="file">{f'<a href="{_safe(github_link)}" target="_blank">{_safe(file_path)}</a>' if github_link else _safe(file_path)}</p>
              <p>{_safe(finding.get('description',''))}</p>
            </article>
            """
        )

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DPDP Report - {_safe(repo_name)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
    .toolbar {{ display: flex; gap: 12px; margin: 16px 0 20px; }}
    input, select {{ padding: 8px; border: 1px solid #cbd5e1; border-radius: 6px; }}
    .grid {{ display: grid; gap: 12px; }}
    .card {{ background: white; border-radius: 10px; padding: 16px; border-left: 6px solid #94a3b8; box-shadow: 0 1px 3px rgba(15,23,42,.08); }}
    .card[data-severity="HIGH"] {{ border-left-color: #b91c1c; }}
    .card[data-severity="MEDIUM"] {{ border-left-color: #d97706; }}
    .card[data-severity="LOW"] {{ border-left-color: #2563eb; }}
    .meta {{ font-size: 12px; color: #475569; display: flex; gap: 10px; }}
    .sev {{ font-weight: 700; }}
    .new {{ color: #b91c1c; font-weight: 700; }}
    .file {{ font-family: Consolas, monospace; color: #334155; }}
  </style>
</head>
<body>
  <h1>DPDP Compliance Report</h1>
  <p><b>Repository:</b> {_safe(repo_name)}<br><b>Score:</b> {_safe(score)} {_safe(grade)}</p>
  <div class="toolbar">
    <input id="search" placeholder="Search findings...">
    <select id="severity">
      <option value="">All severities</option>
      <option>HIGH</option>
      <option>MEDIUM</option>
      <option>LOW</option>
      <option>INFO</option>
      <option>PASS</option>
    </select>
  </div>
  <div class="grid" id="cards">
    {''.join(cards)}
  </div>
  <script>
    const cards = [...document.querySelectorAll('.card')];
    const search = document.getElementById('search');
    const severity = document.getElementById('severity');
    function applyFilters() {{
      const term = search.value.toLowerCase();
      const sev = severity.value;
      for (const card of cards) {{
        const matchesText = card.innerText.toLowerCase().includes(term);
        const matchesSev = !sev || card.dataset.severity === sev;
        card.style.display = matchesText && matchesSev ? '' : 'none';
      }}
    }}
    search.addEventListener('input', applyFilters);
    severity.addEventListener('change', applyFilters);
    window.__DPDP_FINDINGS__ = {findings_json};
  </script>
</body>
</html>"""
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(page)
    return output
