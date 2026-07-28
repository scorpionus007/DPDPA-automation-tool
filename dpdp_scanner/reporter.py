"""
Reporter module.

Responsible for generating human-readable reports from findings.
"""

from __future__ import annotations

import html
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.pdfgen import canvas
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from rich.console import Console

from dpdp_scanner.scan_history import make_finding_key

# Ensure we can print emojis on Windows terminals that default to legacy encodings.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

console = Console()

# Cover page colors
COLOR_DARK = colors.HexColor("#0f172a")
COLOR_ACCENT = colors.HexColor("#b91c1c")
COLOR_TEXT = colors.HexColor("#1e293b")
COLOR_MEDIUM = colors.HexColor("#b45309")
COLOR_INFO = colors.HexColor("#64748b")
COLOR_LIGHT_BG = colors.HexColor("#f1f5f9")
COLOR_BLUE = colors.HexColor("#2563eb")
COLOR_PASS = colors.HexColor("#15803d")
COLOR_GREY = colors.HexColor("#94a3b8")
COLOR_AMBER = colors.HexColor("#d97706")


def _smart_path(path: str, max_len: int = 80) -> str:
    """Truncate path keeping last 2 dirs + filename: '...pkg/auth/user.py'."""
    if not path or len(str(path)) <= max_len:
        return str(path)
    parts = str(path).replace("\\", "/").split("/")
    if len(parts) <= 3:
        return str(path)[:max_len]
    short = "/".join(parts[-3:])
    if len(short) <= max_len:
        return "..." + short
    return "..." + "/".join(parts[-2:])[:max_len - 3]


def _get_priority_label(finding: Dict) -> tuple:
    """
    Return (label, color) for developer-friendly priority.
    - FIX NOW: HIGH severity with high confidence
    - FIX THIS SPRINT: HIGH severity or MEDIUM with high confidence
    - BACKLOG: Everything else (LOW, INFO, low confidence)
    """
    severity = (finding.get("severity") or "").upper()
    confidence = float(finding.get("confidence") or finding.get("llm_confidence") or 0.5)
    requires_human = finding.get("requires_human_validation", False)

    if severity == "HIGH" and confidence >= 0.7 and not requires_human:
        return ("FIX NOW", COLOR_ACCENT)
    elif severity == "HIGH" or (severity == "MEDIUM" and confidence >= 0.7):
        return ("FIX THIS SPRINT", COLOR_AMBER)
    elif severity == "MEDIUM":
        return ("REVIEW & FIX", COLOR_MEDIUM)
    else:
        return ("BACKLOG", COLOR_INFO)


def _priority_pill(label: str, color: Any) -> Table:
    pill = Table([[Paragraph(f"<b>{_reportlab_plaintext(label)}</b>", getSampleStyleSheet()["BodyText"])]])
    pill.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.whitesmoke),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return pill


def _reportlab_plaintext(text: Any) -> str:
    """
    Escape &, <, > for ReportLab Paragraph so LLM/code snippets with HTML or
    pseudo-tags like <label>, <br>, <para> do not break the XML-ish parser.
    """
    if text is None:
        return ""
    return html.escape(_fix_encoding(str(text)), quote=False)


def _fix_encoding(text: str) -> str:
    """Replace corrupted UTF-8 sequences (e.g. mis-decoded em dash) with proper Unicode."""
    if not text:
        return text
    s = str(text)
    # Corrupted em dash (UTF-8 bytes for U+2014 read as Latin-1)
    s = s.replace("\u00e2\u20ac\u2014", "\u2014")
    # Corrupted right single quote
    s = s.replace("\u00e2\u20ac\u2122", "\u2019")
    # Corrupted left double quote
    s = s.replace("\u00e2\u20ac\u0153", "\u201c")
    s = s.replace("\u00e2\u20ac", "\u201c")
    # Corrupted ellipsis
    s = s.replace("\u00e2\u20ac\u2026", "...")
    s = s.replace("\u2018", "'")
    s = s.replace("\u2019", "'")
    return s


def _safe_para(text: Any, style: ParagraphStyle) -> Optional[Paragraph]:
    """Prepare text for ReportLab Paragraph — preserve formatting tags, escape bare ampersands."""
    if not text:
        return None
    text = str(text)
    text = _fix_encoding(text)

    # Fix bare ampersands that aren't already entities
    text = re.sub(r"&(?!(amp|lt|gt|quot|apos|#\d+);)", "&amp;", text)

    # Hard truncate at 3000 chars
    if len(text) > 3000:
        text = text[:2997] + "..."

    try:
        return Paragraph(text, style)
    except Exception:
        # If ReportLab still chokes, strip all tags as fallback
        clean = re.sub(r"<[^>]+>", "", text)
        return Paragraph(clean[:3000], style)


def _render_fix_steps(
    fix: Any, style: ParagraphStyle, bullet_style: ParagraphStyle
) -> List[Any]:
    """Render fix steps as a proper formatted list."""
    if not fix:
        return []
    elements: List[Any] = []
    if isinstance(fix, list):
        for i, step in enumerate(fix):
            step_text = _fix_encoding(re.sub(r"<br\s*/?>", " ", str(step)))
            step_text = re.sub(
                r"&(?!(amp|lt|gt|quot|apos|#\d+);)", "&amp;", step_text
            )
            step_text = re.sub(r"^Step\s*\d+:\s*", "", step_text.strip())
            step_safe = _reportlab_plaintext(step_text)
            elements.append(Paragraph(f"{i+1}. {step_safe}", style))
            elements.append(Spacer(1, 3))
    else:
        raw = _fix_encoding(str(fix))
        parts = re.split(r"<br\s*/?>", raw)
        for i, part in enumerate(parts):
            if part.strip():
                elements.append(
                    Paragraph(f"{i+1}. {_reportlab_plaintext(part.strip())}", style)
                )
                elements.append(Spacer(1, 3))
    return elements


def _section_label(
    label: str,
    label_style: ParagraphStyle,
    content: str,
    content_style: ParagraphStyle,
) -> List[Any]:
    """Render a label + content pair as two paragraphs."""
    elements: List[Any] = []
    if content:
        content_clean = _fix_encoding(re.sub(r"^<b>[^<]+</b>\s*", "", str(content)))
        content_clean = re.sub(
            r"&(?!(amp|lt|gt|quot|apos|#\d+);)", "&amp;", content_clean
        )
        para = _safe_para(content_clean[:3000], content_style)
        if para:
            elements.append(Paragraph(label, label_style))
            elements.append(para)
            elements.append(Spacer(1, 4))
    return elements


def _section_header(title: str, color: Any) -> Paragraph:
    """Render a section header with optional color."""
    style = ParagraphStyle(
        name="SectionHeader",
        parent=getSampleStyleSheet()["Heading2"],
        textColor=color,
    )
    return Paragraph(title, style)


def _make_badge(text: str, color: Any) -> Paragraph:
    """Render a badge-like label (e.g. Overall Risk: HIGH)."""
    style = ParagraphStyle(
        name="Badge",
        parent=getSampleStyleSheet()["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=color,
    )
    return Paragraph(text, style)


def _draw_cover_page(canvas: canvas.Canvas, doc: Any) -> None:
    """Draw professional cover page: repo name, score bar, metadata."""
    w, h = letter
    c = canvas
    repo_name = getattr(doc, "repo_name", "Repository")
    files_indexed = getattr(doc, "files_indexed", 0)
    tech_stack = getattr(doc, "tech_stack", [])
    scan_date = getattr(doc, "scan_date", datetime.now().strftime("%d %B %Y"))
    compliance_score = getattr(doc, "compliance_score", None)

    c.setFillColor(COLOR_DARK)
    c.rect(0, 0, w, h, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(w / 2, h * 0.78, "DPDP COMPLIANCE AUDIT")
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(w / 2, h * 0.70, _fix_encoding(repo_name))
    c.setFont("Helvetica", 12)
    c.setFillColor(COLOR_ACCENT)
    c.drawCentredString(w / 2, h * 0.63, "Digital Personal Data Protection Act 2023")
    c.setStrokeColor(COLOR_ACCENT)
    c.setLineWidth(2)
    c.line(0.5 * inch, h * 0.56, w - 0.5 * inch, h * 0.56)

    if compliance_score:
        score = compliance_score.get("score") or 0
        grade = compliance_score.get("grade", "?")
        grade_lbl = compliance_score.get("grade_label", "")
        if score is None:
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(COLOR_TEXT)
            c.drawCentredString(w / 2, h * 0.48 - 4, "N/A")
            c.setFont("Helvetica", 10)
            c.drawCentredString(
                w / 2,
                h * 0.44,
                _fix_encoding(str(grade_lbl or "Score not applicable")),
            )
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.grey)
            c.drawCentredString(
                w / 2,
                h * 0.40,
                "No indexed source files — run is for triage only.",
            )
        else:
            bar_width = 400
            filled = int(bar_width * score / 100)
            bar_color = (
                COLOR_PASS if score >= 85
                else colors.HexColor("#f5a623") if score >= 55
                else COLOR_ACCENT
            )
            c.setFillColor(bar_color)
            c.rect(w / 2 - bar_width / 2, h * 0.50 - 8, filled, 16, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#e0e0e0"))
            c.rect(w / 2 - bar_width / 2 + filled, h * 0.50 - 8, bar_width - filled, 16, fill=1, stroke=0)
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(colors.white) # Use white for readability on dark background
            c.drawCentredString(w / 2, h * 0.48 - 4, f"{score}/100")
            c.setFont("Helvetica", 11)
            c.drawCentredString(w / 2, h * 0.40, f"Grade {grade} — {grade_lbl}")
    else:
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.white)
        c.drawCentredString(w / 2, h * 0.48, "No compliance score available")

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.grey)
    y_meta = h * 0.34
    meta = getattr(doc, "scan_metadata", {}) or {}
    commit = meta.get("commit_hash", "")
    branch = meta.get("branch", "")
    scanner_ver = meta.get("scanner_version", "")
    if commit:
        c.drawCentredString(w / 2, y_meta, f"Commit: {commit[:12]}  Branch: {branch or 'N/A'}")
        y_meta -= 16
    c.drawCentredString(w / 2, y_meta, f"Scanned: {scan_date}")
    y_meta -= 16
    c.drawCentredString(w / 2, y_meta, f"Files indexed: {files_indexed}")
    y_meta -= 16
    if tech_stack:
        c.drawCentredString(w / 2, y_meta, f"Languages: {', '.join(str(x) for x in tech_stack[:6])}")
        y_meta -= 16
    if scanner_ver:
        c.drawCentredString(w / 2, y_meta, f"Scanner: v{scanner_ver}")
        y_meta -= 16
    cli_flags = meta.get("cli_flags", "")
    if cli_flags:
        c.drawCentredString(w / 2, y_meta, f"Flags: {cli_flags[:80]}")
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(w / 2, h * 0.14, "CONFIDENTIAL — Internal Use Only")

    c.setFillColor(colors.HexColor("#f1f5f9"))
    c.rect(0.5 * inch, 0.3 * inch, w - inch, 0.5 * inch, fill=1, stroke=0)
    c.setFillColor(colors.grey)
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(0.6 * inch, 0.5 * inch, "This report is generated by automated static analysis. Findings are indicative and not legal advice.")


def _draw_header_footer(canvas: canvas.Canvas, doc: Any) -> None:
    """Draw header and footer on content pages (page 2+)."""
    w, h = letter
    repo_name = getattr(doc, "repo_name", "Repository")
    scan_date = getattr(doc, "scan_date", "")
    page_num = canvas.getPageNumber()
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#1a1a2e"))
    canvas.setLineWidth(0.5)
    canvas.line(40, h - 50, w - 40, h - 50)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(40, h - 45, f"DPDP Compliance Report — {_fix_encoding(repo_name)}")
    canvas.drawRightString(w - 40, h - 45, "CONFIDENTIAL")
    canvas.line(40, 40, w - 40, 40)
    canvas.drawString(40, 28, f"Generated by DPDP Scanner — {scan_date}")
    canvas.drawRightString(w - 40, 28, f"Page {page_num}")
    canvas.restoreState()


def _render_data_flow_section(
    flowables: List[Any],
    flow_graph: Optional[Dict],
    body_style: ParagraphStyle,
    subheading_style: ParagraphStyle,
    small_grey_style: ParagraphStyle,
    code_style: ParagraphStyle,
) -> None:
    """Render Data Flow Analysis section: source → intermediary → sink for top PII flows."""
    if not flow_graph:
        return
    flow_paths = flow_graph.get("flow_paths", [])
    if not flow_paths:
        return

    flowables.append(Paragraph("Data Flow Analysis", subheading_style))
    flowables.append(Spacer(1, 4))
    flowables.append(
        Paragraph(
            "The following PII flow signals were inferred via static analysis (import/call adjacency). "
            "These are heuristic code-path chains, not proven runtime traces. "
            "Use them to guide developer review (confirm actual request → handler → service → database paths in your app).",
            body_style,
        )
    )
    flowables.append(Spacer(1, 8))

    SINK_PRIORITY = {
        "analytics": 1,
        "marketing_email": 2,
        "error_logging": 3,
        "logging": 4,
        "cloud_storage": 5,
        "payment_processor": 6,
    }
    sorted_paths = sorted(
        flow_paths,
        key=lambda x: SINK_PRIORITY.get(x.get("sink_type", ""), 99),
    )[:5]

    for i, fp in enumerate(sorted_paths):
        _render_flow_path(
            flowables, fp, i + 1,
            subheading_style, small_grey_style, code_style,
        )


def _render_flow_path(
    flowables: List[Any],
    fp: Dict,
    index: int,
    subtitle_style: ParagraphStyle,
    small_grey_style: ParagraphStyle,
    code_style: ParagraphStyle,
) -> None:
    """Render a single flow path as a visual chain."""
    SINK_LABELS = {
        "analytics": "Analytics SDK",
        "marketing_email": "Marketing Platform",
        "error_logging": "Error Logging Service",
        "cloud_storage": "Cloud Storage",
        "payment_processor": "Payment Processor",
        "logging": "Application Logs",
    }
    sink_type = fp.get("sink_type", "")
    sink_label = SINK_LABELS.get(sink_type, "External Service")
    source_name = (fp.get("source") or "").split("/")[-1]
    sink_name = (fp.get("sink") or "").split("/")[-1]
    pii_list = ", ".join((fp.get("pii_fields") or [])[:3]) or "email, name (inferred)"
    hop_count = fp.get("hop_count", 0)
    path = fp.get("path", [])

    # Show full chain (developer-friendly; avoids "fake flow" impression)
    if isinstance(path, list) and path:
        chain = "  →  ".join(p.split("/")[-1] for p in path[:8])
        if len(path) > 8:
            chain += f"  →  ... ({len(path) - 8} more)"
    else:
        chain = f"{source_name}  →  {sink_name}"

    flowables.append(Paragraph(f"Flow {index}: {sink_label}", subtitle_style))
    flowables.append(Paragraph(f"PII fields: {pii_list}", small_grey_style))
    flowables.append(Paragraph(chain, code_style))
    flowables.append(Spacer(1, 6))


def _render_remediation_roadmap(
    elements: List[Any],
    findings: List[Dict],
    styles: Dict,
) -> None:
    """Generate a 30-day remediation roadmap from findings."""
    actionable = [
        f for f in findings
        if f.get("severity") in ("HIGH", "MEDIUM", "LOW")
        and f.get("rule") != "NO_CROSS_BORDER_DETECTED"
    ]
    if not actionable:
        return

    elements.append(Paragraph("30-Day Remediation Roadmap", styles["section_header"]))
    elements.append(Paragraph(
        "The following plan prioritises findings by severity and estimated effort. "
        "Complete Week 1 items before your next security review.",
        styles.get("body", styles["body_small"]),
    ))
    elements.append(Spacer(1, 8))

    def _hours(f: Dict) -> tuple:
        h = f.get("remediation_hours") or (2, 8)
        if isinstance(h, (list, tuple)) and len(h) >= 2:
            return (h[0], h[1])
        return (2, 8)

    week1 = [f for f in actionable if f.get("severity") == "HIGH"]
    week2 = [f for f in actionable if f.get("severity") == "MEDIUM" and _hours(f)[0] <= 8]
    week3 = [f for f in actionable if f.get("severity") == "MEDIUM" and _hours(f)[0] > 8]
    week4 = [f for f in actionable if f.get("severity") == "LOW"]

    week_configs = [
        ("Week 1 — Critical", week1,
         "Fix immediately — these represent the highest legal exposure.",
         "#FEF2F2", "#DC2626"),
        ("Week 2 — High Priority", week2,
         "Address within 2 weeks — short fixes with significant compliance impact.",
         "#FFF7ED", "#EA580C"),
        ("Week 3 — Significant", week3,
         "Schedule in sprint — requires more engineering time.",
         "#FEFCE8", "#CA8A04"),
        ("Week 4 — Advisory", week4,
         "Address before next compliance review.",
         "#F0FDF4", "#16A34A"),
    ]

    total_min_hours = 0
    total_max_hours = 0

    for week_title, week_findings, week_desc, _bg_hex, color_hex in week_configs:
        if not week_findings:
            continue
        week_min = sum(_hours(f)[0] for f in week_findings)
        week_max = sum(_hours(f)[1] for f in week_findings)
        total_min_hours += week_min
        total_max_hours += week_max

        elements.append(Paragraph(
            f"<b>{week_title}</b>  ({week_min}–{week_max} hours)",
            ParagraphStyle(
                "week_header",
                fontSize=10,
                fontName="Helvetica-Bold",
                textColor=colors.HexColor(color_hex),
                spaceBefore=8,
                spaceAfter=3,
            ),
        ))
        elements.append(Paragraph(week_desc, styles["body_small"]))

        grouped: Dict[tuple, Dict[str, Any]] = {}
        for f in week_findings:
            rule_display = (f.get("rule") or "").replace("_", " ").title()
            file_display = f.get("display_path") or f.get("file") or ""
            if file_display and file_display != "N/A":
                parts = file_display.replace("\\", "/").split("/")
                file_display = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
                file_display = f" — {file_display}"
            elif f.get("affected_count", 0) > 1:
                file_display = f" — {f['affected_count']} files"
            else:
                file_display = ""
            key = (rule_display, file_display)
            if key not in grouped:
                grouped[key] = {
                    "rule_display": rule_display,
                    "file_display": file_display,
                    "hours_min": 0,
                    "hours_max": 0,
                    "count": 0,
                }
            hours_min, hours_max = _hours(f)
            grouped[key]["hours_min"] += hours_min
            grouped[key]["hours_max"] += hours_max
            grouped[key]["count"] += 1

        for item in grouped.values():
            rule_display = item["rule_display"]
            file_display = item["file_display"]
            hours_min = item["hours_min"]
            hours_max = item["hours_max"]
            dup_suffix = f" x{item['count']}" if item["count"] > 1 else ""
            elements.append(Paragraph(
                f"&#9633;  {rule_display}{file_display}{dup_suffix}  "
                f"<font color='grey'>({hours_min}–{hours_max} hrs)</font>",
                ParagraphStyle(
                    "checklist_item",
                    fontSize=8,
                    fontName="Helvetica",
                    leftIndent=12,
                    spaceAfter=2,
                ),
            ))
        elements.append(Spacer(1, 6))

    total_days_min = round(total_min_hours / 8, 1)
    total_days_max = round(total_max_hours / 8, 1)
    elements.append(Paragraph(
        f"<b>Total estimated remediation effort: "
        f"{total_min_hours}–{total_max_hours} hours "
        f"({total_days_min}–{total_days_max} engineering days)</b>",
        styles.get("body", styles["body_small"]),
    ))
    elements.append(Spacer(1, 12))


def _render_delta_section(
    elements: List[Any],
    delta: Optional[Dict],
    previous_scan: Optional[Dict],
    current_score: int,
    styles: Dict,
) -> None:
    """Render before/after comparison (score change, resolved, new)."""
    if not delta or delta.get("is_first_scan"):
        return
    if not previous_scan:
        return

    new_count = delta.get("new_count", 0)
    resolved_count = delta.get("resolved_count", 0)
    unchanged = delta.get("unchanged_count", 0)
    files_changed = delta.get("changed_files_count", 0)
    prev_score = previous_scan.get("score") if previous_scan else 0
    prev_date = previous_scan.get("scanned_at", previous_scan.get("scan_date", "previous scan"))
    if isinstance(prev_date, str) and len(prev_date) > 10:
        prev_date = prev_date[:10]

    score_delta = current_score - prev_score
    score_arrow = "&#9650;" if score_delta > 0 else ("&#9660;" if score_delta < 0 else "—")
    score_color = "#16A34A" if score_delta > 0 else ("#DC2626" if score_delta < 0 else "#6B7280")

    elements.append(Paragraph(
        f"Changes Since {prev_date}",
        styles["section_header"],
    ))
    if score_delta != 0:
        elements.append(Paragraph(
            f"<font color='{score_color}'><b>"
            f"{score_arrow} Score: {prev_score} &#8594; {current_score} "
            f"({'+' if score_delta > 0 else ''}{score_delta} points)"
            f"</b></font>",
            styles.get("body", styles["body_small"]),
        ))
        elements.append(Spacer(1, 4))

    stats = []
    if resolved_count > 0:
        stats.append((f"&#10003;  {resolved_count} finding(s) resolved", "#16A34A"))
    if new_count > 0:
        stats.append((f"&#128279;  {new_count} new finding(s) introduced", "#DC2626"))
    if unchanged > 0:
        stats.append((f"—   {unchanged} finding(s) unchanged", "#6B7280"))
    if files_changed > 0:
        stats.append((f"&#128193;  {files_changed} file(s) changed", "#6B7280"))
    for text, color in stats:
        elements.append(Paragraph(
            f"<font color='{color}'>{text}</font>",
            styles["body_small"],
        ))

    resolved_items = delta.get("resolved_findings", [])
    if resolved_items:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>Resolved since last scan:</b>", styles["body_small"]))
        for item in resolved_items[:8]:
            rule = (item.get("rule") or "").replace("_", " ").title()
            elements.append(Paragraph(
                f"  &#10003;  {rule}",
                ParagraphStyle("resolved_item", fontSize=8, textColor=colors.HexColor("#16A34A"), leftIndent=8, spaceAfter=1),
            ))

    new_items = delta.get("new_findings", [])
    if new_items:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>New findings this scan:</b>", styles["body_small"]))
        for item in new_items[:8]:
            rule = (item.get("rule") or "").replace("_", " ").title()
            severity = item.get("severity", "")
            color = "#DC2626" if severity == "HIGH" else "#EA580C"
            elements.append(Paragraph(
                f"  <font color='{color}'>&#9888;  {rule} [{severity}]</font>",
                ParagraphStyle("new_item", fontSize=8, leftIndent=8, spaceAfter=1),
            ))
    elements.append(Spacer(1, 12))


_LLM_SNIPPET_BOILERPLATE = (
    "this line",
    "this file",
    "this function",
    "this code",
    "the file",
    "the class",
    "defines a",
    "imports the",
    "imports ",
    "contains",
)


def _line_looks_like_llm_prose(s: str) -> bool:
    sl = (s or "").lower()
    return any(p in sl for p in _LLM_SNIPPET_BOILERPLATE)


def _get_evidence_snippet(finding: Dict) -> str:
    """Prefer actual code lines over LLM narrative descriptions."""
    citation = finding.get("citation") or {}
    if isinstance(citation, dict) and citation.get("line_content"):
        return str(citation["line_content"]).strip()[:500]

    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        if evidence.get("line_content"):
            line = str(evidence["line_content"]).strip()
            if line and not _line_looks_like_llm_prose(line):
                return line[:500]
        pii_fields = evidence.get("pii_fields") or []
        if pii_fields:
            first = pii_fields[0]
            if isinstance(first, dict) and first.get("line_content"):
                return str(first["line_content"]).strip()[:500]
    return ""


def _best_line_and_snippet(f: Dict) -> tuple[int | None, str | None, str | None]:
    """
    Line number + snippet: prefer citation / evidence code lines, not LLM prose.
    """
    citation = f.get("citation") or {}
    if isinstance(citation, dict) and citation.get("line_content"):
        ln = citation.get("line_number")
        sn = str(citation["line_content"]).strip()
        if sn:
            if isinstance(ln, int):
                return ln, sn[:220], "Evidence snippet"
            if ln is not None:
                try:
                    return int(ln), sn[:220], "Evidence snippet"
                except (TypeError, ValueError):
                    pass
            return None, sn[:220], "Evidence snippet"

    snippet = _get_evidence_snippet(f)
    ev = f.get("evidence") or {}
    if isinstance(ev, dict) and snippet:
        ln = ev.get("line_number")
        ev_lc = (ev.get("line_content") or "").strip()
        if ev_lc and snippet.strip() == ev_lc[:500].strip():
            if isinstance(ln, int):
                return ln, snippet[:220], "Evidence snippet"
            if ln is not None:
                try:
                    return int(ln), snippet[:220], "Evidence snippet"
                except (TypeError, ValueError):
                    pass
        for key in ("pii_fields", "endpoints", "libraries"):
            lst = ev.get(key) or []
            if not isinstance(lst, list):
                continue
            for item in lst:
                if not isinstance(item, dict):
                    continue
                lc = (item.get("line_content") or "").strip()
                if lc and snippet and (lc in snippet or snippet in lc or lc[:80] == snippet[:80]):
                    ln = item.get("line_number")
                    if isinstance(ln, int):
                        return ln, snippet[:220], "Evidence snippet"
                    if ln is not None:
                        try:
                            return int(ln), snippet[:220], "Evidence snippet"
                        except (TypeError, ValueError):
                            pass
                    return None, snippet[:220], "Evidence snippet"
        if snippet:
            ln = ev.get("line_number")
            if isinstance(ln, int):
                return ln, snippet[:220], "Evidence snippet"
            if ln is not None:
                try:
                    return int(ln), snippet[:220], "Evidence snippet"
                except (TypeError, ValueError):
                    pass
            return None, snippet[:220], "Evidence snippet"

    evr = f.get("evidence_review") or []
    if isinstance(evr, list):
        for item in evr:
            if not isinstance(item, dict):
                continue
            ln = item.get("line_number")
            obs = (item.get("observation") or "").strip()
            if obs and _line_looks_like_llm_prose(obs):
                continue
            if isinstance(ln, int) and obs and len(obs) < 300 and "\n" not in obs[:80]:
                return ln, obs[:220], "AI observation"

    ev2 = f.get("evidence") or {}
    if isinstance(ev2, dict):
        for key in ("pii_fields", "endpoints", "libraries"):
            lst = ev2.get(key) or []
            if not isinstance(lst, list):
                continue
            for item in lst:
                if not isinstance(item, dict):
                    continue
                ln = item.get("line_number")
                line_snip = (item.get("line_content") or "").strip()
                if isinstance(ln, int) and line_snip:
                    return ln, line_snip[:220], "Evidence snippet"
    return None, None, None


def _explain_confidence(finding: Dict) -> str:
    rule = str(finding.get("rule") or "")
    conf = float(finding.get("confidence") or finding.get("llm_confidence") or 0.5)
    ev = finding.get("evidence") or {}
    if rule.startswith("PII_FLOW_") and isinstance(ev, dict):
        flow_ev = ev.get("flow_evidence") or {}
        if isinstance(flow_ev, dict):
            hops = ev.get("hop_count")
            infra = flow_ev.get("infrastructure_intermediates", 0)
            symbol = flow_ev.get("symbol_tracking_score", flow_ev.get("symbol_score", 0))
            taint = flow_ev.get("taint_analysis_score", flow_ev.get("taint_score", 0))
            return (
                f"Confidence {conf:.2f} — {hops} hop path, "
                f"symbol continuity {symbol}, taint {taint}, "
                f"infrastructure intermediates {infra}."
            )
    if rule == "PLAINTEXT_PII_IN_LOGS" and isinstance(ev, dict):
        return (
            f"Confidence {conf:.2f} — {ev.get('logger_context', 'unknown')} logger context, "
            f"structured logger={ev.get('structured_logger', False)}, "
            f"redaction hint={ev.get('redaction_hint', False)}."
        )
    if rule == "CROSS_BORDER_TRANSFER_RISK" and isinstance(ev, dict):
        return (
            f"Confidence {conf:.2f} — match types {', '.join(ev.get('match_types', [])) or 'unknown'}, "
            f"PII payload present={ev.get('pii_payload_present', False)}."
        )
    return f"Confidence {conf:.2f} — based on direct rule evidence and validation context."


def _render_business_summary(
    findings: List[Dict],
    compliance_score: Optional[Dict],
    remediation_effort: Optional[Dict],
    body_style: ParagraphStyle,
) -> Optional[Paragraph]:
    pii_terms = []
    for finding in findings:
        ev = finding.get("evidence") or {}
        if isinstance(ev, dict):
            pii_fields = ev.get("pii_fields") or []
            if isinstance(pii_fields, list):
                pii_terms.extend(str(x) for x in pii_fields[:5])
    pii_terms = [p for p in sorted({p for p in pii_terms if p})[:4]]
    pii_label = ", ".join(pii_terms) if pii_terms else "personal data"
    high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    top_sections = []
    if compliance_score and compliance_score.get("section_breakdown"):
        ordered = sorted(
            compliance_score["section_breakdown"],
            key=lambda row: (row.get("pct", 100), -row.get("weight", 0)),
        )
        top_sections = [row["section"] for row in ordered[:2] if row.get("section")]
    section_text = " and ".join(top_sections) if top_sections else "core DPDP controls"
    effort = remediation_effort or {}
    text = (
        f"This application appears to process {pii_label}. "
        f"It currently has {high_count} high-priority issues concentrated around {section_text}. "
        f"Fixing the top findings is estimated at {effort.get('total_days_min', 0)}–{effort.get('total_days_max', 0)} engineering days."
    )
    return _safe_para(text, body_style)


def _render_risk_heatmap(findings: List[Dict]) -> Drawing:
    sections = [
        "Section 5",
        "Section 6",
        "Section 6(6)",
        "Section 7",
        "Section 8",
        "Section 8(1)",
        "Section 8(3)",
        "Section 8(4)",
        "Section 8(6)",
        "Section 9",
        "Section 11",
        "Section 13 — Grievance Redressal",
        "Section 16",
    ]
    severities = ["HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
    counts: Dict[tuple[str, str], int] = {}
    for finding in findings:
        sec = str(finding.get("dpdp_section") or "")
        sev = str(finding.get("severity") or "").upper()
        section = next((s for s in sections if s in sec), None)
        if not section or sev not in severities:
            continue
        counts[(section, sev)] = counts.get((section, sev), 0) + 1

    cell_w = 60
    cell_h = 16
    draw = Drawing(cell_w * (len(severities) + 1), cell_h * (len(sections) + 1))
    for idx, sev in enumerate(severities, start=1):
        draw.add(String(idx * cell_w + 5, cell_h * len(sections) + 4, sev, fontSize=7))
    for row, section in enumerate(reversed(sections)):
        y = row * cell_h
        draw.add(String(2, y + 4, section[:18], fontSize=6))
        for col, sev in enumerate(severities, start=1):
            count = counts.get((section, sev), 0)
            intensity = min(count, 5)
            fill = (
                COLOR_LIGHT_BG
                if intensity == 0
                else colors.HexColor(["#fee2e2", "#fecaca", "#fca5a5", "#ef4444", "#b91c1c"][intensity - 1])
            )
            draw.add(Rect(col * cell_w, y, cell_w - 2, cell_h - 2, fillColor=fill, strokeColor=COLOR_GREY))
            draw.add(String(col * cell_w + 22, y + 4, str(count), fontSize=7))
    return draw


def generate_report(
    findings: List[Dict],
    output: str,
    gap_findings: Optional[List[Dict]] = None,
    repo_context: Optional[Dict] = None,
    path_to_display: Optional[Dict[str, str]] = None,
    deep_review: Optional[Dict] = None,
    delta: Optional[Dict] = None,
    compliance_score: Optional[Dict] = None,
    remediation_effort: Optional[Dict] = None,
    llm_result: Optional[Dict] = None,
    quiet: bool = False,
    repo_name: Optional[str] = None,
    files_indexed: Optional[int] = None,
    flow_graph: Optional[Dict] = None,
    scan_metadata: Optional[Dict] = None,
    acknowledged_findings: Optional[List[Dict]] = None,
) -> None:
    """
    Generate a PDF report from findings and print a short Rich summary.

    :param findings: Findings (possibly enriched) to report on.
    :param output: Output base path or identifier (e.g. "report" -> report.pdf).
    :param quiet: If True, do not print to console (use when stdout is used for JSON, e.g. GUI bridge).
    """
    if not output.endswith(".pdf"):
        output = f"{output}.pdf"

    # Ensure output directory exists
    out_dir = os.path.dirname(output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        name="BodyWrap",
        parent=styles["Normal"],
        wordWrap="LTR",
        splitLongWords=True,
    )
    code_style = ParagraphStyle(
        name="CodeWrap",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        wordWrap="LTR",
        splitLongWords=True,
    )
    file_style = ParagraphStyle(
        name="FilePath",
        parent=styles["Normal"],
        fontSize=8,
        wordWrap="LTR",
        splitLongWords=True,
    )
    bold_style = ParagraphStyle(
        name="Bold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        wordWrap="LTR",
        splitLongWords=True,
    )
    small_grey_style = ParagraphStyle(
        name="SmallGrey",
        parent=styles["Normal"],
        fontSize=8,
        textColor=COLOR_INFO,
        wordWrap="LTR",
        splitLongWords=True,
    )
    grey_label_style = ParagraphStyle(
        name="GreyLabel",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.grey,
        wordWrap="LTR",
        splitLongWords=True,
    )
    italic_grey_style = ParagraphStyle(
        name="ItalicGrey",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9,
        textColor=colors.grey,
        wordWrap="LTR",
        splitLongWords=True,
    )
    subheading_style = ParagraphStyle(
        name="Subheading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        wordWrap="LTR",
        splitLongWords=True,
    )
    callout_style = ParagraphStyle(
        name="Callout",
        parent=styles["Normal"],
        fontSize=10,
        leftIndent=12,
        rightIndent=12,
        backColor=COLOR_LIGHT_BG,
        borderPadding=8,
        wordWrap="LTR",
        splitLongWords=True,
    )
    small_style = ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontSize=8,
        textColor=COLOR_TEXT,
        wordWrap="LTR",
        splitLongWords=True,
    )
    body_small = ParagraphStyle(
        name="BodySmall",
        parent=styles["Normal"],
        fontSize=8,
        wordWrap="LTR",
        splitLongWords=True,
    )
    section_header_style = ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=12,
        fontName="Helvetica-Bold",
        spaceAfter=6,
    )
    styles_dict = {
        "body_small": body_small,
        "section_header": section_header_style,
        "small_grey": small_grey_style,
        "body": body_style,
    }

    path_map = path_to_display or {}
    _repo_name = repo_name or (repo_context or {}).get("repo_name", "Repository")
    _files_indexed = (
        files_indexed
        if files_indexed is not None
        else (repo_context or {}).get("files_indexed", len(path_map))
    )
    _tech_stack = (
        (repo_context or {}).get("tech_stack")
        or (repo_context or {}).get("tech_stack_deterministic")
        or []
    )
    _scan_date = datetime.now().strftime("%d %B %Y")

    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        topMargin=55,
        bottomMargin=45,
        leftMargin=72,
        rightMargin=72,
    )
    doc.repo_name = _repo_name
    doc.files_indexed = _files_indexed
    doc.tech_stack = _tech_stack
    doc.scan_date = _scan_date
    doc.compliance_score = compliance_score
    doc.remediation_effort = remediation_effort
    doc.findings = findings
    doc.scan_metadata = scan_metadata or {}

    flowables = [PageBreak()]  # first page is cover
    flowables.append(Paragraph("DPDP Compliance Scan Report", styles["Title"]))
    flowables.append(Spacer(1, 12))
    toc_rows = [
        ["Section", "Contents"],
        ["1", "Quick Actions for Developers"],
        ["2", "Executive Summary"],
        ["3", "Compliance Score by Section"],
        ["4", "Scan Coverage and Data Flow Analysis"],
        ["5", "Findings Overview"],
        ["6", "Detailed Findings"],
        ["7", "AI Deep Compliance Review"],
        ["8", "30-Day Remediation Roadmap / Delta"],
    ]
    toc_table = Table(toc_rows, colWidths=[50, 360])
    toc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_LIGHT_BG),
                ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GREY),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    flowables.append(Paragraph("<b>Contents</b>", subheading_style))
    flowables.append(Spacer(1, 6))
    flowables.append(toc_table)
    flowables.append(PageBreak())
    flowables.append(Paragraph("DPDP Compliance Scan Report", styles["Title"]))
    flowables.append(Spacer(1, 12))

    # ══════════════════════════════════════════════════════════════════════════
    # TL;DR — Quick Actions for Developers (developer-friendly at-a-glance)
    # ══════════════════════════════════════════════════════════════════════════
    high_findings = [f for f in findings if (f.get("severity") or "").upper() == "HIGH"]
    medium_findings = [f for f in findings if (f.get("severity") or "").upper() == "MEDIUM"]
    high_count = len(high_findings)
    medium_count = len(medium_findings)
    effort = remediation_effort or {}

    # Build Quick Actions list (top 5 highest priority)
    quick_actions: List[str] = []
    priority_order = high_findings[:3] + medium_findings[:2]
    for f in priority_order:
        rule = f.get("rule", "")
        file_path = f.get("file", "")
        if file_path and file_path not in ("N/A", "REPO-WIDE"):
            short_path = _smart_path(file_path, 50)
            quick_actions.append(f"• <b>{rule}</b> → {short_path}")
        else:
            quick_actions.append(f"• <b>{rule}</b> (codebase-wide)")

    if quick_actions:
        flowables.append(_section_header("Quick Actions for Developers", COLOR_BLUE))
        flowables.append(Spacer(1, 4))
        flowables.append(
            _safe_para(
                "Fix these first to improve your compliance score:",
                small_grey_style,
            )
        )
        flowables.append(Spacer(1, 4))
        for action in quick_actions[:5]:
            flowables.append(_safe_para(action, body_style))
        flowables.append(Spacer(1, 12))

    business_summary = _render_business_summary(
        findings, compliance_score, remediation_effort, body_style
    )
    if business_summary:
        flowables.append(_section_header("What This Means", COLOR_BLUE))
        flowables.append(Spacer(1, 4))
        flowables.append(business_summary)
        flowables.append(Spacer(1, 12))

    # Executive summary — plain English risk statement
    if high_count > 0:
        risk_statement = (
            f"This codebase has {high_count} critical compliance gap(s) that require immediate attention "
            f"under the Digital Personal Data Protection Act 2023. "
            f"An additional {medium_count} significant gap(s) were identified that should be addressed within 30 days. "
            f"The estimated total remediation effort is {effort.get('total_days_min', 0)}–{effort.get('total_days_max', 0)} engineering days."
        )
    else:
        risk_statement = (
            f"No critical compliance gaps were identified. "
            f"{medium_count} moderate gap(s) were found that should be addressed to achieve full DPDP compliance. "
            f"Estimated remediation: {effort.get('total_days_min', 0)}–{effort.get('total_days_max', 0)} engineering days."
        )
    risk_statement = _fix_encoding(risk_statement)
    flowables.append(_safe_para(risk_statement, body_style))
    flowables.append(Spacer(1, 16))

    # Summary with source breakdown (Rule Engine vs Deep Review)
    total = len(findings)
    rule_engine_count = sum(1 for f in findings if f.get("rule") != "DEEP_REVIEW_VALIDATED")
    deep_review_count = sum(1 for f in findings if f.get("rule") == "DEEP_REVIEW_VALIDATED")

    by_severity: Dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or "UNKNOWN").upper()
        by_severity[s] = by_severity.get(s, 0) + 1

    summary_lines = [f"<b>Total findings: {total}</b>"]
    summary_lines.append(f"  • Rule Engine: {rule_engine_count}")
    summary_lines.append(f"  • AI Deep Review: {deep_review_count}")
    summary_lines.append("")
    summary_lines.append("<b>By Severity:</b>")
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO", "PASS"):
        if sev in by_severity:
            summary_lines.append(f"  {sev}: {by_severity[sev]}")

    # Priority breakdown
    fix_now = sum(1 for f in findings if _get_priority_label(f)[0] == "FIX NOW")
    fix_sprint = sum(1 for f in findings if _get_priority_label(f)[0] == "FIX THIS SPRINT")
    if fix_now or fix_sprint:
        summary_lines.append("")
        summary_lines.append("<b>Developer Priority:</b>")
        if fix_now:
            summary_lines.append(f"  Fix Now: {fix_now}")
        if fix_sprint:
            summary_lines.append(f"  Fix This Sprint: {fix_sprint}")

    flowables.append(Paragraph("<br/>".join(summary_lines), styles["Normal"]))
    flowables.append(Spacer(1, 16))

    if (compliance_score and compliance_score.get("score_unreliable")) or _files_indexed == 0:
        flowables.append(
            _safe_para(
                "<b>Disclaimer:</b> This scan did not index any source files (or the score was marked "
                "unreliable). The numeric compliance score does not reflect the repository. "
                "This report is for developer triage only and is not legal advice.",
                italic_grey_style,
            )
        )
        flowables.append(Spacer(1, 12))

    # Repo context summary (if from Layer 1)
    if repo_context and not repo_context.get("error"):
        tech = ", ".join(_tech_stack[:5])
        risk = repo_context.get("risk_surface_summary", "")
        if tech or risk:
            context_text = f"<b>Tech Stack:</b> {tech}<br/><b>Risk Profile:</b> {risk}"
            flowables.append(Paragraph(context_text, body_style))
            flowables.append(Spacer(1, 10))

    # Compliance score section breakdown
    if compliance_score and compliance_score.get("section_breakdown"):
        flowables.append(Paragraph("<b>Compliance score by section</b>", subheading_style))
        flowables.append(Spacer(1, 4))
        section_scores = compliance_score.get("section_scores") or {}
        has_ai_adj = any(
            isinstance(section_scores.get(row.get("section")), dict)
            and section_scores.get(row.get("section"), {}).get("ai_penalty")
            for row in compliance_score["section_breakdown"]
        )
        section_data = [["DPDP Section", "Weight", "Score"] + (["AI Adj."] if has_ai_adj else []) + ["Status"]]
        status_styles = []
        for row in compliance_score["section_breakdown"]:
            status_color = (
                COLOR_PASS if row["status"] == "pass"
                else COLOR_AMBER if row["status"] == "warn"
                else COLOR_ACCENT
            )
            cells = [
                row["section"],
                str(row["weight"]),
                f"{row['earned']}/{row['weight']} ({row['pct']}%)",
            ]
            section_detail = section_scores.get(row["section"], {}) if isinstance(section_scores, dict) else {}
            if has_ai_adj:
                ai_penalty = section_detail.get("ai_penalty") if isinstance(section_detail, dict) else None
                cells.append(f"-{ai_penalty}" if ai_penalty else "—")
            cells.append(row["status"].upper())
            section_data.append(cells)
            status_col = len(cells) - 1
            status_styles.append(("BACKGROUND", (status_col, len(section_data) - 1), (status_col, len(section_data) - 1), status_color))
        col_widths = [110, 45, 110] + ([55] if has_ai_adj else []) + [60]
        sect_table = Table(section_data, colWidths=col_widths)
        sect_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ("TEXTCOLOR", (-1, 1), (-1, -1), colors.whitesmoke),
                ]
                + status_styles
            )
        )
        flowables.append(sect_table)
        flowables.append(Spacer(1, 12))
        flowables.append(Paragraph("<b>Risk Heatmap</b>", subheading_style))
        flowables.append(Spacer(1, 4))
        flowables.append(_render_risk_heatmap(findings))
        flowables.append(Spacer(1, 12))

    # Remediation effort summary
    effort = remediation_effort or {}
    days_min = effort.get("total_days_min", 0)
    days_max = effort.get("total_days_max", 0)
    if days_min > 0 or days_max > 0:
        flowables.append(
            _safe_para(
                f"<b>Estimated Total Remediation Effort: "
                f"{days_min}–{days_max} engineering days</b>",
                callout_style,
            )
        )
        flowables.append(Spacer(1, 12))

    # Scan Coverage section
    _scan_meta = scan_metadata or {}
    _skipped = _scan_meta.get("skipped_files") or []
    _dirs_skipped = _scan_meta.get("dirs_skipped") or []
    if _files_indexed or _skipped:
        flowables.append(Paragraph("<b>Scan Coverage</b>", subheading_style))
        flowables.append(Spacer(1, 4))
        cov_lines = [f"Files analyzed: {_files_indexed}"]
        if _skipped:
            by_reason: Dict[str, int] = {}
            for sk in _skipped:
                r = sk.get("reason", "unknown") if isinstance(sk, dict) else "unknown"
                by_reason[r] = by_reason.get(r, 0) + 1
            cov_lines.append(f"Files skipped: {len(_skipped)}")
            for reason, cnt in sorted(by_reason.items()):
                cov_lines.append(f"  — {reason}: {cnt}")
        if _dirs_skipped:
            cov_lines.append(f"Directories excluded: {', '.join(str(d) for d in _dirs_skipped[:10])}")
        flowables.append(_safe_para("<br/>".join(cov_lines), small_grey_style))
        flowables.append(Spacer(1, 12))

    # Data flow section (PII source → sink flows)
    _render_data_flow_section(
        flowables,
        flow_graph,
        body_style,
        subheading_style,
        small_grey_style,
        code_style,
    )
    if flow_graph and flow_graph.get("flow_paths"):
        flowables.append(Spacer(1, 12))

    # Summary table — use Paragraph in cells so text wraps
    table_cell_style = ParagraphStyle(
        name="TableCell",
        parent=styles["Normal"],
        fontSize=8,
        wordWrap="LTR",
        splitLongWords=True,
    )
    table_data = [
        [
            Paragraph("Rule", bold_style),
            Paragraph("Section", bold_style),
            Paragraph("Severity", bold_style),
            Paragraph("File", bold_style),
        ]
    ]
    for f in findings:
        file_display = path_map.get(f.get("file"), f.get("file", ""))
        table_data.append(
            [
                Paragraph(_fix_encoding(str(f.get("rule", ""))), table_cell_style),
                Paragraph(_fix_encoding(str(f.get("dpdp_section", ""))), table_cell_style),
                Paragraph(str(f.get("severity", "")), table_cell_style),
                Paragraph(_fix_encoding(_smart_path(file_display)), table_cell_style),
            ]
        )
    t = Table(table_data, colWidths=[140, 130, 60, 80])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
            ]
        )
    )
    flowables.append(t)
    flowables.append(Spacer(1, 8))
    n_fallback = sum(1 for f in findings if f.get("llm_enrichment") == "fallback")
    if n_fallback:
        flowables.append(
            _safe_para(
                f"<i>{n_fallback} finding(s) show rule-engine fallback text only "
                "(LLM enrichment cap or parse failure).</i>",
                small_grey_style,
            )
        )
    flow_verifier_checked = 0
    flow_verifier_confirmed = 0
    flow_verifier_uncertain = 0
    for f in findings:
        ev = f.get("evidence") or {}
        if not isinstance(ev, dict):
            continue
        verifier = ev.get("verifier") or {}
        if not isinstance(verifier, dict):
            continue
        verdict = verifier.get("verdict")
        if verdict:
            flow_verifier_checked += 1
            if verdict == "confirmed":
                flow_verifier_confirmed += 1
            elif verdict == "uncertain":
                flow_verifier_uncertain += 1
    if flow_verifier_checked:
        flowables.append(
            _safe_para(
                f"<i>Flow verifier reviewed {flow_verifier_checked} ambiguous flow finding(s): "
                f"{flow_verifier_confirmed} confirmed, {flow_verifier_uncertain} uncertain. "
                "Rejected findings are excluded from this report.</i>",
                small_grey_style,
            )
        )
    flowables.append(Spacer(1, 12))

    # 30-Day Remediation Roadmap
    _render_remediation_roadmap(flowables, findings, styles_dict)

    # Delta / before-after (when we have previous_scan)
    previous_scan = (delta or {}).get("previous_scan") if delta else None
    if previous_scan and compliance_score:
        cur_sc = compliance_score.get("score")
        _render_delta_section(
            flowables,
            delta,
            previous_scan,
            cur_sc if cur_sc is not None else 0,
            styles_dict,
        )
    elif delta and not delta.get("is_first_scan"):
        # Fallback: simple delta table when no previous_scan
        delta_data = [
            [
                Paragraph("New findings this scan", grey_label_style),
                Paragraph(str(delta.get("new_count", 0)), ParagraphStyle("V1", parent=styles["Normal"], textColor=COLOR_ACCENT, fontName="Helvetica-Bold")),
            ],
            [
                Paragraph("Resolved since last scan", grey_label_style),
                Paragraph(str(delta.get("resolved_count", 0)), ParagraphStyle("V2", parent=styles["Normal"], textColor=COLOR_PASS)),
            ],
            [
                Paragraph("Unchanged findings", grey_label_style),
                Paragraph(str(delta.get("unchanged_count", 0)), ParagraphStyle("V3", parent=styles["Normal"], textColor=COLOR_GREY)),
            ],
            [
                Paragraph("Files changed", grey_label_style),
                Paragraph(str(delta.get("changed_files_count", 0)), ParagraphStyle("V4", parent=styles["Normal"], textColor=COLOR_INFO)),
            ],
        ]
        delta_table = Table(delta_data, colWidths=[200, 80])
        delta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), COLOR_LIGHT_BG),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                ]
            )
        )
        flowables.append(Paragraph("<b>Delta vs previous scan</b>", subheading_style))
        flowables.append(Spacer(1, 4))
        flowables.append(delta_table)
        flowables.append(Spacer(1, 16))

    # Per-finding details
    new_keys = set()
    if delta and not delta.get("is_first_scan"):
        new_keys = {make_finding_key(f) for f in delta.get("new_findings", [])}

    flowables.append(Paragraph("Details", styles["Heading2"]))
    flowables.append(Spacer(1, 8))

    badge_style_red = ParagraphStyle(
        name="BadgeRed",
        parent=styles["Normal"],
        fontSize=8,
        textColor=COLOR_ACCENT,
        fontName="Helvetica-Bold",
    )
    badge_style_section = ParagraphStyle(
        name="SectionBadge",
        parent=styles["Normal"],
        fontSize=7,
        textColor=colors.grey,
        backColor=COLOR_LIGHT_BG,
        borderPadding=2,
    )
    total_findings = len(findings)
    severity_bar_color = {"HIGH": COLOR_ACCENT, "MEDIUM": COLOR_AMBER, "LOW": COLOR_INFO}
    priority_rank = {"FIX NOW": 0, "FIX THIS SPRINT": 1, "REVIEW & FIX": 2, "BACKLOG": 3}
    grouped: Dict[str, List[Dict]] = {}
    for finding in findings:
        grouped.setdefault(str(finding.get("dpdp_section") or "Advisory"), []).append(finding)

    preferred_section_order = []
    if compliance_score and compliance_score.get("section_breakdown"):
        preferred_section_order = [row["section"] for row in compliance_score["section_breakdown"]]
    ordered_sections = preferred_section_order + sorted(
        section for section in grouped if section not in preferred_section_order
    )

    card_index = 0
    for section_name in ordered_sections:
        section_findings = grouped.get(section_name) or []
        if not section_findings:
            continue
        section_findings = sorted(
            section_findings,
            key=lambda item: (
                priority_rank.get(_get_priority_label(item)[0], 9),
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}.get((item.get("severity") or "").upper(), 9),
            ),
        )
        counts = {}
        for item in section_findings:
            sev = (item.get("severity") or "").upper()
            counts[sev] = counts.get(sev, 0) + 1
        count_text = ", ".join(f"{sev}: {counts[sev]}" for sev in ("HIGH", "MEDIUM", "LOW", "INFO", "PASS") if sev in counts)
        flowables.append(Paragraph(f"<b>{_reportlab_plaintext(section_name)}</b> ({count_text})", subheading_style))
        flowables.append(Spacer(1, 6))

        for f in section_findings:
            card_index += 1
            severity = (f.get("severity") or "").upper()
            bar_color = severity_bar_color.get(severity, colors.grey)
            section_ref = _fix_encoding(str(f.get("dpdp_section", "")))
            if section_ref:
                section_badge = Paragraph(f"[{section_ref}]", badge_style_section)
            else:
                section_badge = Paragraph("", badge_style_section)

            card_content: List[Any] = []
            priority_label, priority_color = _get_priority_label(f)
            card_content.append(_priority_pill(priority_label, priority_color))
            card_content.append(
                Paragraph(
                    f"Finding {card_index} of {total_findings}",
                    grey_label_style,
                )
            )
            card_content.append(section_badge)
            card_content.append(Spacer(1, 2))

            is_new = make_finding_key(f) in new_keys
            if is_new:
                card_content.append(_safe_para("<b>[NEW]</b>", badge_style_red))

            source_label = ""
            if f.get("rule") == "DEEP_REVIEW_VALIDATED":
                source_label = " [AI Deep Review]"
            elif f.get("llm_enrichment") == "deep_validated":
                source_label = " [AI Validated]"

            rule = _fix_encoding(str(f.get("rule", "")))
            raw_file = f.get("file", "")
            file_display_raw = path_map.get(raw_file, raw_file)
            file_display = _fix_encoding(str(file_display_raw)).replace("/", " / ")
            line_no, snippet, snippet_label = _best_line_and_snippet(f)
            if raw_file == "MULTIPLE" and f.get("affected_count"):
                file_path = f"MULTIPLE ({f.get('affected_count')} files)"
            else:
                if file_display in ("N/A", "", "REPO-WIDE"):
                    file_display = "CODEBASE-WIDE"
                if isinstance(line_no, int):
                    file_path = f"{file_display}:{line_no}"
                else:
                    file_path = file_display
            card_content.append(
                Paragraph(f"<b>{card_index}. [{severity}] {rule}</b>{source_label} — {file_path}", file_style)
            )
            if snippet_label == "AI observation" and not f.get("code_example"):
                snippet = None
            if snippet and snippet_label:
                sn = _safe_para(f"<b>{snippet_label}:</b> {snippet}", small_style)
                if sn:
                    card_content.append(sn)
            confidence_note = _explain_confidence(f)
            if confidence_note:
                card_content.append(_safe_para(f"<i>{_reportlab_plaintext(confidence_note)}</i>", small_grey_style))
            hours = f.get("remediation_hours", (0, 0))
            if isinstance(hours, (list, tuple)) and len(hours) >= 2 and hours[1] > 0:
                card_content.append(
                    _safe_para(
                        f"<b>Estimated fix time:</b> {hours[0]}–{hours[1]} hours",
                        small_style,
                    )
                )
            if f.get("affected_files") and f.get("affected_count", 0) >= 3:
                affected = f["affected_files"]
                parts = [f"  • {p}" for p in affected[:6]]
                if len(affected) > 6:
                    parts.append(f"  • ... and {len(affected) - 6} more files")
                files_text = "<br/>".join(parts)
                aff_para = _safe_para(
                    f"<b>Affected files ({len(affected)}):</b><br/>{files_text}",
                    body_style,
                )
                if aff_para:
                    card_content.append(aff_para)
            desc_para = _safe_para(f.get("description"), body_style)
            if desc_para:
                card_content.append(desc_para)
            if f.get("rule") == "INCOMPLETE_DELETION_COVERAGE":
                ev = f.get("evidence") or {}
                if isinstance(ev, dict):
                    cov = ev.get("coverage_pct")
                    uncovered_entities = ev.get("uncovered_entities") or []
                    covered_entities = ev.get("covered_entities") or []
                    if cov is not None:
                        card_content.append(
                            _safe_para(
                                f"<b>Entity deletion coverage:</b> {cov}% "
                                f"({len(covered_entities)} covered / {len(uncovered_entities)} uncovered)",
                                body_style,
                            )
                        )
                    if uncovered_entities:
                        show = ", ".join(str(x) for x in uncovered_entities[:8])
                        if len(uncovered_entities) > 8:
                            show += f", and {len(uncovered_entities) - 8} more"
                        card_content.append(
                            _safe_para(
                                f"<b>Uncovered entities:</b> {_reportlab_plaintext(show)}",
                                body_style,
                            )
                        )
                    entity_to_files = ev.get("entity_to_files") or {}
                    if isinstance(entity_to_files, dict) and entity_to_files:
                        hints = []
                        def _short_hint_path(p: str) -> str:
                            parts = str(p).replace("\\", "/").split("/")
                            return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
                        for ent in uncovered_entities[:5]:
                            files = entity_to_files.get(ent) or []
                            if isinstance(files, list) and files:
                                short_files = [
                                    _short_hint_path(str(p)) if isinstance(p, str) else str(p)
                                    for p in files[:2]
                                ]
                                hints.append(f"{ent}: {', '.join(short_files)}")
                        if hints:
                            hint_text = "; ".join(hints)
                            card_content.append(
                                _safe_para(
                                    f"<b>Entity→file hints:</b> {_reportlab_plaintext(hint_text)}",
                                    body_style,
                                )
                            )
            rule_name = f.get("rule") or ""
            if rule_name.startswith("PII_FLOW_") or rule_name == "PII_FLOW_PURPOSE_MISMATCH":
                flow_ev = (f.get("evidence") or {}).get("flow_evidence")
                if isinstance(flow_ev, dict):
                    fe_lines = ["<b>Flow Analysis</b>"]
                    for label, key in [
                        ("Structural score", "structural_score"),
                        ("Symbol tracking", "symbol_tracking_score"),
                        ("Taint analysis", "taint_analysis_score"),
                        ("ML confidence", "ml_confidence"),
                        ("Consent proximity", "consent_proximity"),
                        ("Quality penalty", "quality_penalty"),
                    ]:
                        val = flow_ev.get(key)
                        if val is not None:
                            fe_lines.append(f"  {label}: {val}")
                    if len(fe_lines) > 1:
                        card_content.append(
                            _safe_para("<br/>".join(fe_lines), small_grey_style)
                        )
            risk = f.get("risk_explanation")
            if risk:
                risk_text = " ".join(str(x) for x in risk) if isinstance(risk, list) else str(risk)
                card_content.extend(_section_label("Risk:", bold_style, risk_text, body_style))
            fix = f.get("fix")
            if fix:
                card_content.append(Paragraph("Fix:", bold_style))
                card_content.extend(_render_fix_steps(fix, body_style, body_style))
            if f.get("dpdp_reference"):
                card_content.extend(
                    _section_label(
                        "DPDP:",
                        bold_style,
                        f.get("dpdp_reference", ""),
                        body_style,
                    )
                )
            code_ex = f.get("code_example")
            if code_ex:
                card_content.extend(
                    _section_label(
                        "Example:",
                        bold_style,
                        _reportlab_plaintext(code_ex),
                        code_style,
                    )
                )

            _page_w = letter[0]
            _content_w = _page_w - getattr(doc, "leftMargin", 72) - getattr(doc, "rightMargin", 72) - 8 - 16
            finding_table = Table(
                [["", card_content]],
                colWidths=[8, _content_w],
            )
            finding_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), bar_color),
                        ("LEFTPADDING", (1, 0), (1, -1), 10),
                        ("RIGHTPADDING", (1, 0), (1, -1), 10),
                        ("TOPPADDING", (1, 0), (1, -1), 8),
                        ("BOTTOMPADDING", (1, 0), (1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            flowables.append(finding_table)
            flowables.append(Spacer(1, 12))

    if acknowledged_findings:
        flowables.append(Spacer(1, 12))
        flowables.append(Paragraph("Acknowledged Findings", styles["Heading2"]))
        flowables.append(
            _safe_para(
                "These findings matched repository suppressions and were excluded from the score, but are shown for reviewer transparency.",
                small_grey_style,
            )
        )
        for finding in acknowledged_findings[:12]:
            label = finding.get("suppression_reason") or "suppressed by config"
            flowables.append(
                _safe_para(
                    f"• <b>{_reportlab_plaintext(str(finding.get('rule', '')))}</b> — "
                    f"{_reportlab_plaintext(str(finding.get('file', 'N/A')))} "
                    f"({_reportlab_plaintext(label)})",
                    body_style,
                )
            )
        flowables.append(Spacer(1, 8))

    # Gap findings section
    if gap_findings:
        flowables.append(Spacer(1, 20))
        flowables.append(Paragraph("AI-Identified Compliance Gaps", styles["Heading2"]))
        flowables.append(
            Paragraph(
                "The following gaps were identified by AI analysis and cross-validated. "
                "These are advisory observations, not verified rule violations. "
                "Human review is required before acting on these findings.",
                italic_grey_style,
            )
        )
        flowables.append(Spacer(1, 10))

        for gap in gap_findings:
            verdict = gap.get("skeptic_verdict", "retained")
            card_color = COLOR_MEDIUM if verdict == "retained" else COLOR_INFO

            gap_title = _reportlab_plaintext(
                gap.get("title") or gap.get("gap_id") or ""
            )
            gap_data = [
                [
                    Paragraph(f"[AI-INFERRED] {gap_title}", bold_style),
                    Paragraph(
                        f"Confidence: {int(gap.get('confidence', 0.5) * 100)}%",
                        small_grey_style,
                    ),
                ],
                [
                    Paragraph(
                        _reportlab_plaintext(gap.get("dpdp_section", "")),
                        grey_label_style,
                    ),
                    "",
                ],
                [
                    Paragraph(
                        _reportlab_plaintext(gap.get("observation", "")),
                        body_style,
                    ),
                    "",
                ],
                [
                    Paragraph(
                        f"Recommendation: {_reportlab_plaintext(gap.get('recommendation', ''))}",
                        body_style,
                    ),
                    "",
                ],
            ]

            gap_table = Table(gap_data, colWidths=[380, 100])
            gap_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), COLOR_LIGHT_BG),
                        ("LINECOLOR", (0, 0), (-1, -1), card_color),
                        ("BOX", (0, 0), (-1, -1), 1, card_color),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            flowables.append(gap_table)
            flowables.append(Spacer(1, 8))

    # Deep Review Synthesis (AI-powered analysis)
    dr = deep_review or (llm_result.get("deep_review") if llm_result else None)
    if dr and isinstance(dr, dict) and (dr.get("synthesis") or dr.get("findings")):
        synthesis = dr.get("synthesis") or {}
        chunk_results = dr.get("chunk_results", {})
        is_delta_rev = dr.get("is_delta", False)

        title = (
            "AI Deep Compliance Review (Delta — Changed Files Only)"
            if is_delta_rev
            else "AI Deep Compliance Review"
        )
        flowables.append(Spacer(1, 20))
        flowables.append(_section_header(title, COLOR_BLUE))

        # Explain how deep review integrates with rule engine
        flowables.append(
            _safe_para(
                "This section shows AI analysis that identified compliance gaps beyond "
                "deterministic rules. Validated findings are integrated into the main "
                "findings list above with [AI Deep Review] labels.",
                small_grey_style,
            )
        )
        flowables.append(Spacer(1, 8))

        risk_level = synthesis.get("overall_risk_level") or synthesis.get("overall_risk", "UNKNOWN")
        risk_color = {
            "CRITICAL": COLOR_ACCENT,
            "HIGH": COLOR_ACCENT,
            "MEDIUM": COLOR_MEDIUM,
            "LOW": COLOR_PASS,
        }.get(str(risk_level).upper(), COLOR_INFO)
        
        flowables.append(_make_badge(f"Overall Risk: {risk_level}", risk_color))
        flowables.append(Spacer(1, 6))
        
        narr = synthesis.get("risk_narrative") or synthesis.get("summary", "")
        if narr:
            flowables.append(_safe_para(_reportlab_plaintext(str(narr)), body_style))
        flowables.append(Spacer(1, 8))

        days = synthesis.get("estimated_remediation_days")
        if days is not None:
            flowables.append(
                _safe_para(
                    f"<b>Estimated remediation:</b> {days} engineering day(s)",
                    body_style,
                )
            )

        fix = synthesis.get("single_most_important_fix") or synthesis.get("critical_action", "")
        if fix:
            _page_w, _page_h = letter
            _m_left = getattr(doc, "leftMargin", 72)
            _m_right = getattr(doc, "rightMargin", 72)
            _c_width = _page_w - _m_left - _m_right
            
            # Use a Table to prevent overlapping and ensure professional padding
            fix_table = Table(
                [[Paragraph(f"<b>Most Critical Action:</b> {_reportlab_plaintext(str(fix))}", callout_style)]],
                colWidths=[_c_width]
            )
            fix_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), COLOR_LIGHT_BG),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ]))
            flowables.append(fix_table)
        flowables.append(Spacer(1, 12))

        # Cross-cutting themes
        themes = synthesis.get("cross_cutting_themes", [])
        if themes:
            for theme in themes[:3]:
                if not isinstance(theme, dict): continue
                layers = ", ".join(theme.get("layers_affected", []) or [])
                flowables.append(
                    _safe_para(
                        f"• <b>{_reportlab_plaintext(theme.get('theme', ''))}</b> "
                        f"[{_reportlab_plaintext(theme.get('severity', ''))}] — "
                        f"{_reportlab_plaintext(theme.get('dpdp_section', ''))} — layers: "
                        f"{_reportlab_plaintext(layers)}",
                        body_style,
                    )
                )
            flowables.append(Spacer(1, 8))

        # Top Findings
        top_f = synthesis.get("top_5_findings", [])
        if top_f:
            for f in top_f:
                if not isinstance(f, dict): continue
                sev = f.get("severity", "MEDIUM")
                obs = (f.get("observation") or "")[:500]
                flowables.append(
                    _safe_para(
                        f"<b>{_reportlab_plaintext(str(f.get('rank', '')))}. [{_reportlab_plaintext(str(sev))}] "
                        f"{_reportlab_plaintext(f.get('title', ''))}</b> — "
                        f"{_reportlab_plaintext(f.get('file', ''))} — "
                        f"{_reportlab_plaintext(f.get('dpdp_section', ''))}<br/>"
                        f"{_reportlab_plaintext(obs)}",
                        body_style,
                    )
                )
                flowables.append(Spacer(1, 4))
            flowables.append(Spacer(1, 8))

        # Layer Breakdown
        if chunk_results:
            flowables.append(_safe_para("<b>Layer Breakdown</b>", subheading_style))
            for name, result in chunk_results.items():
                if not isinstance(result, dict): continue
                count = len(result.get("findings", []))
                note = result.get("architectural_note", "")
                flowables.append(
                    _safe_para(
                        f"<b>{_reportlab_plaintext(name)}</b> — {count} finding(s). "
                        f"{_reportlab_plaintext(note)}",
                        body_style,
                    )
                )

    doc.build(
        flowables,
        onFirstPage=_draw_cover_page,
        onLaterPages=_draw_header_footer,
    )
    if not quiet:
        console.print(f"[green]Report saved to[/green] [bold]{output}[/bold]")
