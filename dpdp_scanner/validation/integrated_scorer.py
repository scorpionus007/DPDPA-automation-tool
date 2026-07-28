"""
Integrated scorer — combines rule-engine findings with AI-validated gaps.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from dpdp_scanner.rule_engine import compute_compliance_score

SECTION_WEIGHTS = {
    "Section 6": 22,
    "Section 6(6)": 8,
    "Section 7": 4,
    "Section 8(1)": 18,
    "Section 8": 10,
    "Section 8(3)": 8,
    "Section 8(4)": 8,
    "Section 8(6)": 8,
    "Section 9": 6,
    "Section 11": 6,
    "Section 16": 4,
    "Section 5": 2,
    "Section 13 — Grievance Redressal": 4,
}

TOTAL_WEIGHT = sum(SECTION_WEIGHTS.values())

AI_GAP_WEIGHT_MULTIPLIER = 0.6
MAX_AI_POINT_DELTA = 8.0


def _extract_section(dpdp_section: str) -> str:
    from dpdp_scanner.section_mapping import score_section_key_from_dpdp
    key = score_section_key_from_dpdp(dpdp_section or "")
    return key or "Section 5"


def _grade_label(grade: str) -> str:
    return {
        "A": "Strong",
        "B": "Adequate",
        "C": "Needs Work",
        "D": "At Risk",
        "F": "Critical",
    }.get(grade, "")


def compute_integrated_score(
    rule_findings: List[Dict],
    ai_gaps: List[Dict],
    rejected_findings: List[Dict],
    indexed_file_count: int | None = None,
) -> Dict[str, Any]:
    base_score_data = compute_compliance_score(
        rule_findings, indexed_file_count=indexed_file_count
    )
    rule_score = int(base_score_data.get("score") or 0)

    ai_penalty = 0.0
    section_ai_penalties: Dict[str, float] = {}

    for gap in ai_gaps:
        if not gap.get("dual_validated"):
            continue

        confidence = float(gap.get("confidence", 0.5))
        severity = (gap.get("severity") or "MEDIUM").upper()
        section = _extract_section(str(gap.get("dpdp_section", "")))
        weight = SECTION_WEIGHTS.get(section, 2)

        SEVERITY_PENALTY = {
            "HIGH": 0.30,
            "MEDIUM": 0.15,
            "LOW": 0.05,
            "INFO": 0.02,
        }
        base_penalty = weight * SEVERITY_PENALTY.get(severity, 0.10)
        effective_penalty = (
            base_penalty * confidence * AI_GAP_WEIGHT_MULTIPLIER
        )

        ai_penalty += effective_penalty
        section_ai_penalties[section] = (
            section_ai_penalties.get(section, 0.0) + effective_penalty
        )

    raw_delta = ai_penalty / TOTAL_WEIGHT * 100
    capped_delta = max(0.0, min(MAX_AI_POINT_DELTA, raw_delta))
    raw_integrated = rule_score - capped_delta
    integrated_score = max(0, min(100, round(raw_integrated)))

    grade = (
        "A" if integrated_score >= 85 else
        "B" if integrated_score >= 70 else
        "C" if integrated_score >= 55 else
        "D" if integrated_score >= 40 else
        "F"
    )

    section_detail: Dict[str, Dict[str, Any]] = {}
    for row in base_score_data.get("section_breakdown", []):
        sec = row["section"]
        section_detail[sec] = {
            "earned": row["earned"],
            "weight": row["weight"],
            "pct": row["pct"],
            "status": row.get("status", ""),
        }

    for section, penalty in section_ai_penalties.items():
        if section not in section_detail:
            w = SECTION_WEIGHTS.get(section, 2)
            section_detail[section] = {
                "earned": float(w),
                "weight": w,
                "pct": 100,
                "status": "pass",
            }
        section_detail[section]["ai_penalty"] = round(penalty, 2)
        try:
            current = float(section_detail[section]["earned"])
            section_detail[section]["integrated_earned"] = max(
                0.0, round(current - penalty, 2)
            )
        except (TypeError, ValueError):
            section_detail[section]["integrated_earned"] = 0.0

    penalty_data: Dict[str, Any] = {"available": False}
    try:
        from dpdp_scanner import penalty as penalty_mod  # type: ignore

        if hasattr(penalty_mod, "compute_penalty_exposure"):
            all_confirmed = list(rule_findings) + list(ai_gaps)
            penalty_data = penalty_mod.compute_penalty_exposure(all_confirmed)
            penalty_data["available"] = True
    except Exception:
        pass

    total_rule = len(rule_findings) + len(rejected_findings)
    stats = {
        "rule_findings_total": total_rule,
        "rule_findings_confirmed": len(rule_findings),
        "rule_findings_rejected": len(rejected_findings),
        "ai_gaps_total": len(ai_gaps),
        "ai_gaps_confirmed": sum(1 for g in ai_gaps if g.get("dual_validated")),
    }

    return {
        "integrated_score": integrated_score,
        "rule_engine_score": rule_score,
        "ai_penalty_applied": round(capped_delta, 1),
        "ai_delta_applied": round(capped_delta, 1),
        "grade": grade,
        "grade_label": _grade_label(grade),
        "section_scores": section_detail,
        "section_ai_penalties": section_ai_penalties,
        "penalty_exposure": penalty_data,
        "rejected_finding_count": len(rejected_findings),
        "validation_stats": stats,
        "section_breakdown": base_score_data.get("section_breakdown", []),
    }
