"""Organization-wide compliance PDF and HTML reports."""

from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_org_report(
    org_id: int,
    db_session,
    report_id: Optional[int] = None,
) -> Dict[str, Any]:
    from backend.models import (
        CrossRepoEdge,
        Organization,
        OrgEntity,
        OrgEntityOccurrence,
        Repository,
        Scan,
    )

    org = db_session.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise ValueError("Organization not found")

    repos = db_session.query(Repository).filter(Repository.org_id == org_id).all()
    scans = (
        db_session.query(Scan)
        .filter(Scan.org_id == org_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest: Dict[Any, Scan] = {}
    for s in scans:
        key = s.repository_id or s.repo_name
        if key not in latest:
            latest[key] = s
    active = list(latest.values())

    entity_count = db_session.query(OrgEntity).filter(OrgEntity.org_id == org_id).count()
    edges = (
        db_session.query(CrossRepoEdge)
        .filter(CrossRepoEdge.org_id == org_id)
        .limit(200)
        .all()
    )

    rule_cross: Counter = Counter()
    vendor_cross: Counter = Counter()
    for s in active:
        if not s.compliance_data:
            continue
        for f in s.compliance_data.get("findings") or []:
            rule_cross[f.get("rule", "UNKNOWN")] += 1
            ev = f.get("evidence") or {}
            if isinstance(ev, dict):
                lib = ev.get("library") or ev.get("service")
                if lib:
                    vendor_cross[str(lib)] += 1

    avg_score = (
        sum(s.score or 0 for s in active) / len(active) if active else 0
    )
    grade = (
        "A" if avg_score >= 85 else "B" if avg_score >= 70 else "C" if avg_score >= 50 else "D"
    )

    reports_dir = os.path.join("backend", "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    safe_slug = re.sub(r"[^\w\-.]+", "_", org.slug)[:40]
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_filename = f"org_report_{safe_slug}_{ts}.pdf"
    html_filename = f"org_report_{safe_slug}_{ts}.html"
    pdf_path = os.path.join(reports_dir, pdf_filename)
    html_path = os.path.join(reports_dir, html_filename)

    _write_pdf(
        pdf_path,
        org,
        active,
        repos,
        avg_score,
        grade,
        rule_cross,
        vendor_cross,
        entity_count,
        edges,
        db_session,
    )
    _write_html(
        html_path,
        org,
        active,
        avg_score,
        grade,
        rule_cross,
        entity_count,
        len(edges),
    )

    summary = {
        "org_slug": org.slug,
        "score": int(avg_score),
        "grade": grade,
        "repos_scanned": len(active),
        "repos_total": len(repos),
        "entity_count": entity_count,
        "edge_count": len(edges),
        "top_rules": rule_cross.most_common(10),
    }

    if report_id:
        from backend.models import OrgReport

        report = db_session.query(OrgReport).filter(OrgReport.id == report_id).first()
        if report:
            report.pdf_path = f"/static/reports/{pdf_filename}"
            report.html_path = f"/static/reports/{html_filename}"
            report.summary_json = summary

    return {
        "pdf_path": f"/static/reports/{pdf_filename}",
        "html_path": f"/static/reports/{html_filename}",
        "summary": summary,
    }


def _write_pdf(path, org, active, repos, avg_score, grade, rule_cross, vendor_cross, entity_count, edges, db):
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("OrgTitle", parent=styles["Title"], fontSize=20, spaceAfter=12)
    doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=inch, leftMargin=inch, topMargin=inch, bottomMargin=inch)
    story = []

    story.append(Paragraph(f"Organization Compliance Report — {org.display_name}", title_style))
    story.append(Paragraph(f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("<b>1. Executive Summary</b>", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Scanned <b>{len(active)}</b> of <b>{len(repos)}</b> repositories. "
            f"Organization score: <b>{int(avg_score)}/100</b> (Grade {grade}). "
            f"Knowledge base tracks <b>{entity_count}</b> PII entities across repos.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>2. Per-Repository Matrix</b>", styles["Heading2"]))
    matrix_data = [["Repository", "Score", "HIGH", "MEDIUM", "LOW", "Last Scan"]]
    for s in sorted(active, key=lambda x: x.score or 0)[:50]:
        matrix_data.append([
            s.repo_name[:40],
            str(s.score or 0),
            str(s.findings_high or 0),
            str(s.findings_medium or 0),
            str(s.findings_low or 0),
            s.created_at.strftime("%Y-%m-%d") if s.created_at else "—",
        ])
    t = Table(matrix_data, colWidths=[2.2 * inch, 0.6 * inch, 0.5 * inch, 0.6 * inch, 0.5 * inch, 0.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>3. Top Cross-Cutting Risks</b>", styles["Heading2"]))
    for rule, count in rule_cross.most_common(15):
        story.append(Paragraph(f"• {rule}: present in <b>{count}</b> repo(s)", styles["Normal"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>4. Shared Vendor Exposure</b>", styles["Heading2"]))
    if vendor_cross:
        for vendor, count in vendor_cross.most_common(15):
            story.append(Paragraph(f"• {vendor}: <b>{count}</b> repo(s)", styles["Normal"]))
    else:
        story.append(Paragraph("No aggregated vendor signals in stored findings.", styles["Normal"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>5. Cross-Repo Entity Catalog (sample)</b>", styles["Heading2"]))
    from backend.models import OrgEntity, OrgEntityOccurrence, Repository

    entities = (
        db.query(OrgEntity)
        .filter(OrgEntity.org_id == org.id)
        .order_by(OrgEntity.occurrence_count.desc())
        .limit(25)
        .all()
    )
    for ent in entities:
        repo_ids = {
            o.repository_id
            for o in db.query(OrgEntityOccurrence)
            .filter(OrgEntityOccurrence.org_entity_id == ent.id)
            .all()
        }
        story.append(
            Paragraph(
                f"• <b>{ent.canonical_name}</b> — {len(repo_ids)} repo(s), "
                f"{ent.occurrence_count or 0} occurrence(s)",
                styles["Normal"],
            )
        )
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>6. Inter-Repo Data-Flow Edges (sample)</b>", styles["Heading2"]))
    repo_names = {r.id: r.full_name for r in repos}
    for edge in edges[:30]:
        story.append(
            Paragraph(
                f"• {repo_names.get(edge.src_repo_id, '?')} → "
                f"{repo_names.get(edge.dst_repo_id, '?')} "
                f"(entity id {edge.org_entity_id}, conf {edge.confidence:.0%})",
                styles["Normal"],
            )
        )

    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("<b>7–8. Remediation & Section Roll-Up</b>", styles["Heading2"]))
    section_agg: Dict[str, List[float]] = defaultdict(list)
    for s in active:
        for item in (s.compliance_data or {}).get("section_breakdown") or []:
            section_agg[item.get("section", "?")].append(float(item.get("pct", 0)))
    for sec, pcts in sorted(section_agg.items()):
        avg_pct = int(sum(pcts) / len(pcts)) if pcts else 0
        story.append(Paragraph(f"• {sec}: avg {avg_pct}% across {len(pcts)} repo(s)", styles["Normal"]))

    doc.build(story)


def _write_html(path, org, active, avg_score, grade, rule_cross, entity_count, edge_count):
    rows = "".join(
        f"<tr><td>{s.repo_name}</td><td>{s.score}</td>"
        f"<td>{s.findings_high}</td><td>{s.findings_medium}</td></tr>"
        for s in active[:100]
    )
    rules = "".join(f"<li>{r} ({c} repos)</li>" for r, c in rule_cross.most_common(20))
    if not rules:
        rules = "<li>None recorded</li>"
    html = (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Org Report — {org.display_name}</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0}"
        ".card{background:#1e293b;border-radius:8px;padding:1.5rem;margin-bottom:1rem}"
        "table{width:100%;border-collapse:collapse} th,td{border:1px solid #334155;padding:8px}"
        "th{background:#334155} h1{color:#38bdf8}</style></head><body>"
        f"<h1>{org.display_name} — Organization Compliance</h1>"
        f"<motion class='card'><h2>Score: {int(avg_score)}/100 (Grade {grade})</h2>"
        f"<p>Repos scanned: {len(active)} | Entities: {entity_count} | "
        f"Cross-repo edges: {edge_count}</p></motion>"
        f"<motion class='card'><h2>Repositories</h2>"
        f"<table><tr><th>Repo</th><th>Score</th><th>H</th><th>M</th></tr>{rows}</table></motion>"
        f"<motion class='card'><h2>Cross-Cutting Risks</h2><ul>{rules}</ul></motion>"
        "</body></html>"
    )
    html = html.replace("<motion", "<div").replace("</motion>", "</div>")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
