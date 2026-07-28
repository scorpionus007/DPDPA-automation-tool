"""
Rule: GRIEVANCE_OFFICER_MISSING / GRIEVANCE_OFFICER_PRESENT
DPDP Act 2023 Section 13 — mechanism for Data Principals to register grievances;
designated officer contact details should be published.

PASS only when there is a **clear grievance signal** (officer text, DPO contact, or
dedicated route) **and** either a **contact email** in the repo or a **dedicated
grievance/DPO route**. Generic `/privacy` alone is not sufficient.

Tiny repos without a dedicated grievance route are treated skeptically.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Natural language + identifiers + env (not URL-only — those are routes below)
GRIEVANCE_OFFICER_PATTERNS = [
    r"grievance[_\-\s]?officer",
    r"grievance[_\-\s]?redressal",
    r"grievance[_\-\s]?(cell|desk|team)\b",
    r"data[_\-\s]?protection[_\-\s]?officer",
    r"\bDPO\b(?=\s*[:(\-]|\s+email|\s+contact|\s+at\s)",
    r"dpo[_\-\s]?(email|contact|phone|address)\b",
    r"privacy[_\-\s]?officer(?!\s*policy)",
    r"nodal[_\-\s]?officer",
    r"grievance[_\-\s]?(email|contact|phone)\b",
    r"grievanceOfficer\b",
    r"grievanceContact\b",
    r"GrievanceOfficer\b",
    r"GrievancePage\b",
    r"GrievanceForm\b",
    r"ContactDPO\b",
    r"DataProtectionOfficer\b",
    r"dpoEmail\b",
    r"dpo_email\b",
    r"grievance_officer_email\b",
    r"privacyOfficerEmail\b",
    r"\bGRIEVANCE_OFFICER\b",
    r"\bDPO_EMAIL\b",
    r"\bDPO_CONTACT\b",
    r"\bPRIVACY_OFFICER_EMAIL\b",
    r"\bNODAL_OFFICER\b",
    r"\bshikayat\b",
    r"\bparivad\b",
]

# Dedicated routes / links (strong structural signal)
GRIEVANCE_ROUTE_PATTERNS = [
    r'href\s*=\s*["\']/grievance',
    r'["\']/grievance\b',
    r'["\']/contact[-_]dpo\b',
    r'["\']/dpo\b(?![a-z])',
    r"/complaint\b(?!\w)",
    r'(?:href|to|pathname|path|from)\s*=\s*["\'][^"\']*grievance[^"\']*["\']',
    r'["\']/[^"\'\s<>#?]*grievance[^"\'\s<>#?]*["\']',
    r'(?:href|to|pathname|path|from)\s*=\s*["\'][^"\']*'
    r'(?:data[-_/.\s]?protection|dataprotection)[^"\']*["\']',
    r'["\']/[^"\'\s<>#?]*(?:data[-_/.\s]?protection|dataprotection)[^"\'\s<>#?]*["\']',
]

# --- Weak: common site chrome only (for MISSING evidence — never alone for PASS) ---
_GENERIC_SUPPORT_PATTERNS = [
    (r'["\']/privacy\b', "/privacy link"),
    (r'["\']/help\b', "/help link"),
    (r'["\']/contact\b', "/contact link"),
    (r'["\']/contact[-_]us\b', "/contact-us link"),
    (r"\bPrivacyPolicy\b", "PrivacyPolicy component"),
    (r"privacy[_\-\s]?policy", "privacy policy text"),
    (r"\bHelpCenter\b", "HelpCenter"),
    (r"\bSupportPage\b", "SupportPage"),
    (r"\bContactPage\b", "ContactPage"),
    (r"\bFeedbackForm\b", "FeedbackForm"),
]


def _collect_generic_support_flags(all_content: str) -> List[str]:
    found: List[str] = []
    for pattern, label in _GENERIC_SUPPORT_PATTERNS:
        if re.search(pattern, all_content, re.IGNORECASE):
            found.append(label)
    return found


def _first_evidence_path(
    file_contents: Dict[str, str],
    patterns: List[str],
) -> Tuple[str, str]:
    """Return (path, matched_snippet) for first file matching any pattern."""
    for path, content in file_contents.items():
        for pat in patterns:
            m = re.search(pat, content, re.IGNORECASE)
            if m:
                return path, m.group(0)[:80]
    return "N/A", ""


def run(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []

    if extracted.get("is_framework_library", False):
        return findings

    pii_fields = extracted.get("pii_fields", []) or []
    auth_files = extracted.get("auth_files", []) or []
    if not pii_fields or not auth_files:
        return findings

    file_contents = extracted.get("_file_contents", {}) or {}
    all_content = "\n".join(file_contents.values())

    has_grievance_term = any(
        re.search(p, all_content, re.IGNORECASE) for p in GRIEVANCE_OFFICER_PATTERNS
    )
    has_grievance_route = any(
        re.search(p, all_content, re.IGNORECASE) for p in GRIEVANCE_ROUTE_PATTERNS
    )
    has_contact_info = bool(
        re.search(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            all_content,
        )
    )

    # Dedicated route or officer-style text counts as “grievance context”
    has_grievance_context = has_grievance_term or has_grievance_route

    grievance_officer_present = (
        has_grievance_context
        and (has_contact_info or has_grievance_route)
        and not extracted.get("is_micro_app", False)
    )

    files_count = extracted.get("files_count") or len(file_contents)
    if files_count < 10 and not has_grievance_route:
        grievance_officer_present = False

    generic_flags = _collect_generic_support_flags(all_content)

    if grievance_officer_present:
        ev_path, ev_snip = _first_evidence_path(
            file_contents,
            GRIEVANCE_ROUTE_PATTERNS + GRIEVANCE_OFFICER_PATTERNS,
        )
        match_bits = []
        if has_grievance_route:
            match_bits.append("dedicated route")
        if has_grievance_term:
            match_bits.append("officer/DPO-style text")
        if has_contact_info:
            match_bits.append("contact email")
        match_label = ", ".join(match_bits) or "grievance signal"

        findings.append(
            {
                "rule": "GRIEVANCE_OFFICER_PRESENT",
                "dpdp_section": "Section 13 — Grievance Redressal",
                "severity": "PASS",
                "confidence": 0.82,
                "file": ev_path,
                "display_path": ev_path,
                "description": (
                    "Grievance redressal signal meets stricter checks "
                    f"({match_label}). Consistent with Section 13 intent."
                ),
                "evidence": {
                    "evidence_file": ev_path,
                    "snippet": ev_snip,
                    "has_grievance_route": has_grievance_route,
                    "has_contact_info": has_contact_info,
                    "generic_support_links_also_present": bool(generic_flags),
                },
                "fix": None,
            }
        )
    else:
        findings.append(
            {
                "rule": "GRIEVANCE_OFFICER_MISSING",
                "dpdp_section": "Section 13 — Grievance Redressal",
                "severity": "HIGH",
                "confidence": 0.84,
                "file": "N/A",
                "display_path": "N/A",
                "description": (
                    "No compliant Grievance Officer / DPO publication found. "
                    "A PASS requires grievance-related text or a dedicated route **and** "
                    "a contact email or dedicated grievance/DPO URL. "
                    "Tiny repos without a grievance route are not marked PASS."
                ),
                "evidence": {
                    "generic_support_only": generic_flags[:12],
                    "has_grievance_term": has_grievance_term,
                    "has_grievance_route": has_grievance_route,
                    "has_contact_info": has_contact_info,
                    "is_micro_app": extracted.get("is_micro_app", False),
                    "files_count": files_count,
                },
                "fix": [
                    "Publish a named Grievance Officer (or DPO) with email and, if possible, "
                    "postal address in your privacy policy or legal page.",
                    "Add a dedicated route (e.g. /grievance or /contact-dpo) or config keys "
                    "such as GRIEVANCE_OFFICER_EMAIL referenced from that page.",
                    "Describe the redressal process: how to lodge a grievance, expected "
                    "timeline (e.g. 30 days), and escalation path.",
                ],
                "requires_human_validation": False,
            }
        )

    return findings


def check_grievance(extracted: Dict) -> List[Dict]:
    """Alias for rule_engine compatibility."""
    return run(extracted)
