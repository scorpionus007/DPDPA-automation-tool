"""
Rule engine module.

Responsible for running compliance rules over extracted data.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from dpdp_scanner.section_mapping import score_section_key_from_dpdp

from rich.console import Console
from rich.table import Table

from dpdp_scanner.config import get_finding_override, is_finding_suppressed
from dpdp_scanner.feedback import load_false_positive_penalties
from dpdp_scanner.rules.consent import check_consent
from dpdp_scanner.rules.deletion import check_deletion
from dpdp_scanner.rules.third_party import check_third_party
from dpdp_scanner.rules.retention import check_retention
from dpdp_scanner.rules.security import check_security
from dpdp_scanner.rules.purpose import check_purpose
from dpdp_scanner.rules.childrens_data import check_childrens_data
from dpdp_scanner.rules.breach import check_breach_indicators
from dpdp_scanner.rules.cross_border import check_cross_border
from dpdp_scanner.rules import audit_trail
from dpdp_scanner.rules import consent_withdrawal
from dpdp_scanner.rules import data_access
from dpdp_scanner.rules import data_flow
from dpdp_scanner.rules import grievance


console = Console()


def _deduplicate_findings(findings: list) -> list:
    """
    Collapse multiple findings with the same rule and root cause into one
    finding with a count and all affected files listed.

    Rules:
    - Group findings by rule name
    - If a rule has 3+ findings of same severity → collapse into one
    - The collapsed finding lists all affected files in evidence
    - Single findings (1-2) are never collapsed — they stay as-is
    - PASS and INFO findings are never collapsed
    """
    from collections import defaultdict

    COLLAPSIBLE_RULES = {
        "CONSENT_MISSING",
        "CONSENT_WITHDRAWAL_MISSING",
        "AUDIT_TRAIL_MISSING",
        "AUDIT_TRAIL_PARTIAL",
        "THIRD_PARTY_PII_SHARING",
        "PURPOSE_LIMITATION_RISK",
        "PASSWORD_NOT_HASHED",
        "PLAINTEXT_PII_IN_LOGS",
        "HARDCODED_SECRET",
        "RETENTION_MISSING",
        "CHILDRENS_DATA_RISK",
        "CHILDRENS_DATA_PATTERN",
        "DATA_ACCESS_MISSING",
        "DATA_PORTABILITY_MISSING",
    }

    grouped = defaultdict(list)
    non_collapsible = []

    for f in findings:
        rule = f.get("rule", "")
        severity = f.get("severity", "")
        file_val = f.get("file", "N/A")

        if severity in ("PASS", "INFO") or file_val in ("N/A", "REPO-WIDE"):
            non_collapsible.append(f)
            continue

        if rule in COLLAPSIBLE_RULES:
            grouped[rule].append(f)
        else:
            non_collapsible.append(f)

    result = list(non_collapsible)

    for rule, group in grouped.items():
        if len(group) < 3:
            result.extend(group)
        else:
            base = dict(group[0])
            affected_files = [g.get("display_path", g.get("file", "")) for g in group]
            affected_files_original = [g.get("file", "") for g in group]

            merged_evidence: Dict = {"affected_files": affected_files}
            for g in group:
                ev = g.get("evidence", {})
                if not isinstance(ev, dict):
                    continue
                for k, v in ev.items():
                    if k == "affected_files":
                        continue
                    if isinstance(v, list):
                        merged_evidence.setdefault(k, []).extend(v)
                    elif isinstance(v, dict):
                        merged_evidence.setdefault(k, {}).update(v)
                    elif k not in merged_evidence:
                        merged_evidence[k] = v
            for k, v in merged_evidence.items():
                if isinstance(v, list) and len(v) > 15:
                    merged_evidence[k] = v[:15]

            base["file"] = "MULTIPLE"
            base["display_path"] = "MULTIPLE"
            base["affected_files"] = affected_files
            base["affected_files_original"] = affected_files_original
            base["affected_count"] = len(group)
            base["description"] = (
                f"{base['description'].split('.')[0]}. "
                f"Detected in {len(group)} files: "
                + ", ".join(p.split("/")[-1] for p in affected_files[:4])
                + (f" and {len(affected_files) - 4} more" if len(affected_files) > 4 else "")
            )
            base["evidence"] = merged_evidence
            result.append(base)

    SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}
    result.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 3))

    return result


def compute_compliance_score(
    findings: list,
    indexed_file_count: Optional[int] = None,
) -> dict:
    """
    Compute a 0-100 DPDP compliance score from rule findings.
    Returns dict with overall score, per-section scores, and grade.

    Section 6 uses partial consent logic (missing vs present counts). The score
    reflects the rule engine only, not post-LLM severity changes.

    If indexed_file_count == 0, score is None and score_unreliable is True (no
    source files were analyzed).
    """
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

    RULE_TO_SECTION = {
        "CONSENT_MISSING": "Section 6",
        "CONSENT_MISSING_REPO_LEVEL": "Section 6",
        "CONSENT_PRESENT": "Section 6",
        "INTERNAL_ROUTE_PII_ACCESS": "Section 7",
        "CONSENT_PRESENT_VIA_IMPORT": "Section 6",
        "CONSENT_WITHDRAWAL_MISSING": "Section 6(6)",
        "CONSENT_WITHDRAWAL_PRESENT": "Section 6(6)",
        "HARDCODED_SECRET": "Section 8(1)",
        "PASSWORD_NOT_HASHED": "Section 8(1)",
        "PLAINTEXT_PII_IN_LOGS": "Section 8(1)",
        "NO_DELETION_MECHANISM": "Section 8",
        "DELETION_MECHANISM_PRESENT": "Section 8",
        "RETENTION_MISSING": "Section 8(3)",
        "RETENTION_PRESENT": "Section 8(3)",
        "AUDIT_TRAIL_MISSING": "Section 8(4)",
        "AUDIT_TRAIL_PARTIAL": "Section 8(4)",
        "AUDIT_TRAIL_ADEQUATE": "Section 8(4)",
        "AUDIT_TRAIL_PRESENT": "Section 8(4)",
        "NO_LOGGING_DETECTED": "Section 8(6)",
        "DB_AUDIT_LOGGING_DETECTED": "Section 8(6)",
        "NO_ERROR_HANDLING_IN_AUTH": "Section 8(6)",
        "NO_BREACH_ALERTING": "Section 8(6)",
        "MINIMAL_CONSOLE_LOGGING": "Section 8(6)",
        "BREACH_INDICATORS_ADEQUATE": "Section 8(6)",
        "CHILDRENS_DATA_RISK": "Section 9",
        "AGE_VERIFICATION_PRESENT": "Section 9",
        "DATA_ACCESS_MISSING": "Section 11",
        "DATA_PORTABILITY_MISSING": "Section 11",
        "DATA_ACCESS_PRESENT": "Section 11",
        "DATA_PORTABILITY_PRESENT": "Section 11",
        "CROSS_BORDER_TRANSFER_RISK": "Section 16",
        "NON_INDIA_REGION_CONFIG": "Section 16",
        "NO_CROSS_BORDER_DETECTED": "Section 16",
        "THIRD_PARTY_PII_SHARING": "Section 5",
        "PURPOSE_LIMITATION_RISK": "Section 5",
        "PII_FLOW_PURPOSE_MISMATCH": "Section 5",
        "NO_THIRD_PARTY_DATA_SHARING": "Section 5",
        "GRIEVANCE_OFFICER_MISSING": "Section 13 — Grievance Redressal",
        "GRIEVANCE_OFFICER_PRESENT": "Section 13 — Grievance Redressal",
        "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT": "Section 6",
        "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT": "Section 6",
        "PII_FLOW_TO_LOGGING": "Section 8(1)",
        "INCOMPLETE_DELETION_COVERAGE": "Section 8",
    }

    if indexed_file_count == 0:
        total_possible = sum(SECTION_WEIGHTS.values())
        section_breakdown = []
        for section, weight in SECTION_WEIGHTS.items():
            section_breakdown.append({
                "section": section,
                "weight": weight,
                "earned": 0.0,
                "pct": 0,
                "highs": 0,
                "mediums": 0,
                "passes": 0,
                "status": "fail",
            })
        return {
            "score": None,
            "grade": "N/A",
            "grade_label": "No indexed source files",
            "section_breakdown": section_breakdown,
            "total_possible": total_possible,
            "total_earned": 0.0,
            "score_unreliable": True,
            "score_unreliable_reason": "no_indexed_source_files",
        }

    DEDUCTIONS = {
        "HIGH": 1.00,
        "MEDIUM": 0.50,
        "LOW": 0.15,
        "INFO": 0.00,
        "PASS": -0.20,
    }

    section_scores = {s: float(w) for s, w in SECTION_WEIGHTS.items()}
    section_findings = {s: [] for s in SECTION_WEIGHTS}
    section_penalties = {s: 0.0 for s in SECTION_WEIGHTS}
    section_bonuses = {s: 0.0 for s in SECTION_WEIGHTS}

    SECTION_6_CONSENT_RULES = {
        "CONSENT_MISSING",
        "CONSENT_MISSING_REPO_LEVEL",
        "CONSENT_PRESENT",
        "CONSENT_PRESENT_VIA_IMPORT",
    }

    s6_flow_penalty = 0.0

    for f in findings:
        if f.get("scorable") is False:
            continue
        rule = f.get("rule", "")
        severity = f.get("severity", "INFO")
        section = RULE_TO_SECTION.get(rule)
        if not section:
            section = score_section_key_from_dpdp(str(f.get("dpdp_section") or ""))
        if not section or section not in section_scores:
            continue
        section_findings[section].append(f)
        if section == "Section 6" and rule in SECTION_6_CONSENT_RULES:
            continue
        weight = SECTION_WEIGHTS[section]
        deduction = DEDUCTIONS.get(severity, 0) * weight
        if section == "Section 6":
            s6_flow_penalty += max(0.0, deduction)
        else:
            if deduction >= 0:
                section_penalties[section] += deduction
            else:
                section_bonuses[section] += abs(deduction)

    # Section 6 — separate consent math from flow-rule deductions
    w6 = SECTION_WEIGHTS["Section 6"]
    s6_findings = section_findings.get("Section 6", [])
    consent_missing_findings = [
        f
        for f in s6_findings
        if f.get("rule") in ("CONSENT_MISSING", "CONSENT_MISSING_REPO_LEVEL")
        and f.get("severity") in ("HIGH", "MEDIUM")
    ]
    consent_present_findings = [
        f
        for f in s6_findings
        if f.get("rule") in ("CONSENT_PRESENT", "CONSENT_PRESENT_VIA_IMPORT")
    ]
    if consent_missing_findings and not consent_present_findings:
        consent_subscore = 0
    elif consent_missing_findings and consent_present_findings:
        total = len(consent_missing_findings) + len(consent_present_findings)
        coverage = len(consent_present_findings) / total if total else 0
        consent_subscore = int(coverage * w6)
    else:
        consent_subscore = w6
    capped_s6_flow_penalty = min(s6_flow_penalty, 0.60 * w6)
    consent_floor = 0.0
    if consent_present_findings and not any(
        f.get("severity") == "HIGH" for f in consent_missing_findings
    ):
        consent_floor = 0.20 * w6
    section_scores["Section 6"] = max(
        consent_floor,
        min(w6, consent_subscore - capped_s6_flow_penalty),
    )

    for section, weight in SECTION_WEIGHTS.items():
        if section == "Section 6":
            continue
        penalty_cap = 0.85 * weight
        bonus_cap = 0.20 * weight
        earned = weight - min(penalty_cap, section_penalties[section])
        earned += min(bonus_cap, section_bonuses[section])
        section_scores[section] = max(0.0, min(weight, earned))

    total_possible = sum(SECTION_WEIGHTS.values())
    total_earned = sum(section_scores.values())
    score = round((total_earned / total_possible) * 100)

    if score >= 85:
        grade, grade_label = "A", "Strong"
    elif score >= 70:
        grade, grade_label = "B", "Adequate"
    elif score >= 55:
        grade, grade_label = "C", "Needs Work"
    elif score >= 40:
        grade, grade_label = "D", "At Risk"
    else:
        grade, grade_label = "F", "Critical"

    section_breakdown = []
    for section, weight in SECTION_WEIGHTS.items():
        earned = section_scores[section]
        pct = round((earned / weight) * 100) if weight else 0
        flist = section_findings[section]
        highs = sum(1 for f in flist if f.get("severity") == "HIGH")
        mediums = sum(1 for f in flist if f.get("severity") == "MEDIUM")
        passes = sum(1 for f in flist if f.get("severity") == "PASS")
        section_breakdown.append({
            "section": section,
            "weight": weight,
            "earned": round(earned, 1),
            "pct": pct,
            "highs": highs,
            "mediums": mediums,
            "passes": passes,
            "status": (
                "pass" if pct >= 80
                else "warn" if pct >= 50
                else "fail"
            ),
        })

    return {
        "score": score,
        "grade": grade,
        "grade_label": grade_label,
        "section_breakdown": section_breakdown,
        "total_possible": total_possible,
        "total_earned": round(total_earned, 1),
    }


# Reasonable fix-time estimates (hours min–max) for remediation roadmap
REMEDIATION_EFFORT = {
    "CONSENT_MISSING": (2, 8),
    "CONSENT_MISSING_REPO_LEVEL": (4, 16),
    "CONSENT_WITHDRAWAL_MISSING": (1, 4),
    "AUDIT_TRAIL_MISSING": (4, 12),
    "AUDIT_TRAIL_PARTIAL": (2, 8),
    "HARDCODED_SECRET": (0.5, 2),
    "PASSWORD_NOT_HASHED": (1, 3),
    "PLAINTEXT_PII_IN_LOGS": (1, 3),
    "NO_DELETION_MECHANISM": (2, 6),
    "RETENTION_MISSING": (2, 8),
    "NO_LOGGING_DETECTED": (2, 6),
    "NO_ERROR_HANDLING_IN_AUTH": (1, 3),
    "NO_BREACH_ALERTING": (2, 6),
    "MINIMAL_CONSOLE_LOGGING": (0.5, 2),
    "CHILDRENS_DATA_RISK": (2, 8),
    "DATA_ACCESS_MISSING": (2, 6),
    "DATA_PORTABILITY_MISSING": (2, 8),
    "CROSS_BORDER_TRANSFER_RISK": (4, 12),
    "NON_INDIA_REGION_CONFIG": (4, 12),
    "THIRD_PARTY_PII_SHARING": (2, 6),
    "PURPOSE_LIMITATION_RISK": (2, 6),
    "GRIEVANCE_OFFICER_MISSING": (1, 4),
    "DEEP_REVIEW_VALIDATED": (2, 8),
    "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT": (2, 8),
    "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT": (2, 8),
    "PII_FLOW_TO_LOGGING": (1, 4),
    "PII_FLOW_PURPOSE_MISMATCH": (2, 6),
    "INCOMPLETE_DELETION_COVERAGE": (4, 16),
    "INTERNAL_ROUTE_PII_ACCESS": (1, 4),
}


def attach_remediation_effort(findings: list) -> list:
    """Attach remediation_hours to each finding. PASS/INFO get zero."""
    for f in findings:
        rule = f.get("rule", "")
        severity = f.get("severity", "INFO")

        if severity in ("PASS", "INFO"):
            f["remediation_hours"] = (0, 0)
            continue

        base = REMEDIATION_EFFORT.get(rule)
        if not base:
            base = {"HIGH": (4, 16), "MEDIUM": (2, 8), "LOW": (1, 4)}.get(
                severity, (1, 4)
            )

        count = f.get("affected_count", 1)
        if count > 1:
            scale = 1 + (count - 1) * 0.3
            base = (round(base[0] * scale), round(base[1] * scale))

        f["remediation_hours"] = base

    return findings


def compute_total_effort(findings: list) -> dict:
    """Sum remediation hours across all non-PASS findings."""
    total_min = total_max = 0
    by_severity = {"HIGH": (0, 0), "MEDIUM": (0, 0), "LOW": (0, 0)}

    for f in findings:
        hours = f.get("remediation_hours", (0, 0))
        severity = f.get("severity", "INFO")
        total_min += hours[0]
        total_max += hours[1]
        if severity in by_severity:
            prev = by_severity[severity]
            by_severity[severity] = (prev[0] + hours[0], prev[1] + hours[1])

    return {
        "total_hours_min": total_min,
        "total_hours_max": total_max,
        "total_days_min": round(total_min / 8, 1),
        "total_days_max": round(total_max / 8, 1),
        "by_severity": by_severity,
    }


def _rule_debug_summary(extracted: Dict, rule_name: str) -> str:
    """Return a short summary of inputs relevant for debug (file counts, key signals)."""
    fc = extracted.get("_file_contents") or {}
    n_files = len(fc)
    route_files = extracted.get("route_files") or []
    model_files = extracted.get("model_files") or []
    pii_fields = extracted.get("pii_fields") or []
    flow_paths = (extracted.get("pii_flow_graph") or {}).get("flow_paths") or []
    third_party = extracted.get("third_party_imports") or []
    consent = extracted.get("consent_signals") or []
    deletion = extracted.get("deletion_signals") or []
    retention = extracted.get("retention_signals") or []
    internal = extracted.get("internal_route_files") or []
    user_facing = extracted.get("user_facing_route_files") or []

    if "consent" in rule_name.lower():
        return f"routes={len(route_files)}, user_facing={len(user_facing)}, internal={len(internal)}, consent_signals={len(consent)}"
    if "consent_withdrawal" in rule_name.lower():
        return f"routes={len(route_files)}, consent_signals={len(consent)}"
    if "audit" in rule_name.lower():
        return f"routes={len(route_files)}, files={n_files}"
    if "third_party" in rule_name.lower():
        return f"third_party_imports={len(third_party)}, route_files={len(route_files)}"
    if "deletion" in rule_name.lower():
        deletion_endpoints = extracted.get("deletion_endpoints") or []
        return f"deletion_signals={len(deletion)}, deletion_endpoints={len(deletion_endpoints)}, model_files={len(model_files)}"
    if "retention" in rule_name.lower():
        return f"retention_signals={len(retention)}, model_files={len(model_files)}"
    if "security" in rule_name.lower() or "password" in rule_name.lower() or "secret" in rule_name.lower():
        return f"files={n_files}, auth_files={len(extracted.get('auth_files') or [])}"
    if "purpose" in rule_name.lower():
        return f"route_files={len(route_files)}, pii_fields={len(pii_fields)}"
    if "children" in rule_name.lower():
        return f"route_files={len(route_files)}, pii_fields={len(pii_fields)}"
    if "breach" in rule_name.lower():
        return f"route_files={len(route_files)}, auth-like routes checked, files={n_files}"
    if "cross_border" in rule_name.lower():
        return f"files={n_files}, model_files={len(model_files)}, pii_files={len({p.get('file') for p in pii_fields if p.get('file')})}"
    if "data_flow" in rule_name.lower():
        return f"flow_paths={len(flow_paths)}, pii_flow_graph present={bool(extracted.get('pii_flow_graph'))}"
    if "data_access" in rule_name.lower():
        return f"route_files={len(route_files)}, pii_fields={len(pii_fields)}"
    return f"files={n_files}"


def run_rules(
    extracted: Dict,
    config: Optional[Dict] = None,
    quiet: bool = False,
    debug: bool = False,
) -> Tuple[List[Dict], dict, dict]:
    """
    Run compliance rules on extracted data and return findings, score, and effort.

    :param extracted: Extracted data from the extractor.
    :param config: Optional config dict (consent_skip_path_segments, suppressions) from load_config.
    :param quiet: If True, do not print the rule table or score (use when LLM will run and report is after LLM).
    :param debug: If True, print per-rule debug line (inputs summary + finding count and rule names).
    :return: (findings, compliance_score, remediation_effort).
    """
    findings: List[Dict] = []

    # Inject config so consent rule can use suppressions and skip segments
    extracted_with_config = {**extracted, "_config": config or {}}

    rule_calls = [
        ("consent", lambda: check_consent(extracted_with_config)),
        ("consent_withdrawal", lambda: consent_withdrawal.run(extracted)),
        ("audit_trail", lambda: audit_trail.run(extracted)),
        ("third_party", lambda: check_third_party(extracted)),
        ("deletion", lambda: check_deletion(extracted)),
        ("retention", lambda: check_retention(extracted)),
        ("security", lambda: check_security(extracted)),
        ("purpose", lambda: check_purpose(extracted)),
        ("childrens_data", lambda: check_childrens_data(extracted)),
        ("breach", lambda: check_breach_indicators(extracted)),
        ("cross_border", lambda: check_cross_border(extracted)),
        ("data_flow", lambda: data_flow.run(extracted)),
        ("data_access", lambda: data_access.run(extracted)),
        ("grievance", lambda: grievance.run(extracted)),
    ]

    for name, call in rule_calls:
        rule_findings = call()
        findings.extend(rule_findings)
        if debug:
            by_rule = {}
            for f in rule_findings:
                r = f.get("rule", "?")
                by_rule[r] = by_rule.get(r, 0) + 1
            parts = [f"{r}({n})" for r, n in sorted(by_rule.items())]
            summary = _rule_debug_summary(extracted, name)
            console.print(
                f"  [dim][rule] {name}: {summary} → {len(rule_findings)} finding(s): {', '.join(parts) or 'none'}[/dim]"
            )

    fp_penalties = load_false_positive_penalties()
    if fp_penalties:
        for finding in findings:
            penalty = fp_penalties.get(str(finding.get("rule") or ""))
            if not penalty:
                continue
            old_conf = float(finding.get("confidence", 0.5) or 0.5)
            finding["confidence"] = round(max(0.05, old_conf - penalty), 2)
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                evidence = {}
                finding["evidence"] = evidence
            evidence["false_positive_penalty"] = penalty

    if config and config.get("overrides"):
        for finding in findings:
            override = get_finding_override(finding, config["overrides"])
            if not override:
                continue
            if override.get("severity"):
                finding["severity"] = override["severity"]
            if override.get("confidence") is not None:
                try:
                    finding["confidence"] = float(override["confidence"])
                except (TypeError, ValueError):
                    pass
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                evidence = {}
                finding["evidence"] = evidence
            evidence["override_reason"] = override.get("reason") or "config override"

    deployment_class = extracted.get("deployment_class")
    if deployment_class == "self_hosted_oss":
        severity_downgrade = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}
        for finding in findings:
            if finding.get("rule") not in {
                "GRIEVANCE_OFFICER_MISSING",
                "DATA_PORTABILITY_MISSING",
            }:
                continue
            current = (finding.get("severity") or "INFO").upper()
            finding["severity"] = severity_downgrade.get(current, current)
            finding["confidence"] = max(
                0.35,
                round(float(finding.get("confidence", 0.5) or 0.5) - 0.10, 2),
            )
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                evidence = {}
                finding["evidence"] = evidence
            evidence["deployment_class"] = deployment_class
            evidence["deployment_note"] = (
                "Self-hosted OSS repository detected; final operator obligations may sit with deployers."
            )

    # Apply config suppressions (rule + path_glob) before dedupe
    if config and config.get("suppressions"):
        acknowledged = []
        remaining = []
        for finding in findings:
            if is_finding_suppressed(finding, config["suppressions"]):
                copy_f = dict(finding)
                copy_f["status"] = "suppressed"
                copy_f["acknowledged"] = True
                copy_f["suppression_reason"] = next(
                    (
                        s.get("reason", "")
                        for s in config["suppressions"]
                        if (s.get("rule") or "").strip() == (finding.get("rule") or "").strip()
                        and s.get("path_glob")
                        and finding.get("file")
                        and is_finding_suppressed(finding, [s])
                    ),
                    "",
                )
                acknowledged.append(copy_f)
            else:
                remaining.append(finding)
        extracted["_acknowledged_findings"] = acknowledged
        findings = remaining
    else:
        extracted["_acknowledged_findings"] = []

    findings = _deduplicate_findings(findings)
    findings = attach_remediation_effort(findings)
    effort = compute_total_effort(findings)
    n_indexed = len(extracted.get("_file_contents") or {})
    score = compute_compliance_score(findings, indexed_file_count=n_indexed)

    path_to_display = extracted.get("path_to_display", {})

    if not quiet:
        severity_order = ("HIGH", "MEDIUM", "LOW", "INFO", "PASS")
        severity_key = {s: i for i, s in enumerate(severity_order)}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_key.get((f.get("severity") or "").upper(), 99), f.get("rule", "")),
        )

        table = Table(title="Rule Engine Summary")
        table.add_column("Rule", style="bold")
        table.add_column("Section")
        table.add_column("Severity")
        table.add_column("Confidence")
        table.add_column("File")

        for finding in sorted_findings:
            conf = finding.get("confidence")
            conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) else "-"
            file_display = path_to_display.get(finding.get("file"), finding.get("file"))
            if finding.get("affected_count"):
                file_display = f"MULTIPLE ({finding['affected_count']} files)"
            table.add_row(
                str(finding.get("rule", "")),
                str(finding.get("dpdp_section", "")),
                str(finding.get("severity", "")),
                conf_str,
                str(file_display),
            )

        console.print(table)

        score_val = score["score"]
        grade = score["grade"]
        grade_label = score["grade_label"]
        console.print(
            f"\n[bold]DPDP Compliance Score: "
            f"[{'green' if score_val >= 85 else 'yellow' if score_val >= 55 else 'red'}]{score_val}/100 — "
            f"Grade {grade} ({grade_label})[/bold]"
        )
        days_min = effort["total_days_min"]
        days_max = effort["total_days_max"]
        console.print(
            f"[bold]Estimated remediation: {days_min}–{days_max} engineering days[/bold]"
        )

    return findings, score, effort


if __name__ == "__main__":
    # Allow running as a script: `python dpdp_scanner/rule_engine.py`
    import os
    import sys

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from dpdp_scanner.config import load_config
    from dpdp_scanner.ingestor import ingest
    from dpdp_scanner.extractor import extract

    repo_files, repo_path = ingest(".")
    extracted = extract(repo_files)
    config = load_config(repo_path)
    findings, score, effort = run_rules(extracted, config)

    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['rule']} — {f['file']}")

