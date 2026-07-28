"""
Map free-text dpdp_section strings to canonical scoring keys.
"""

from __future__ import annotations

import re
from typing import Optional

# Canonical DPDP sections used for legal-grounding checks.
VALID_DPDP_SECTIONS = tuple(f"Section {n}" for n in range(1, 31))

# Keys must match rule_engine.SECTION_WEIGHTS.
# Specific subsections must appear before their parent sections.
_SCORE_SECTION_KEYS = (
    "Section 6(6)",
    "Section 8(1)",
    "Section 8(3)",
    "Section 8(4)",
    "Section 8(6)",
    "Section 13 — Grievance Redressal",
    "Section 6",
    "Section 7",
    "Section 8",
    "Section 9",
    "Section 11",
    "Section 16",
    "Section 5",
)

_SECTION_PATTERNS = (
    ("Section 6(6)", (r"\bsection\s*6\s*\(\s*6\s*\)\b", r"\bconsent withdrawal\b")),
    (
        "Section 8(1)",
        (
            r"\bsection\s*8\s*\(\s*1\s*\)\b",
            r"\bsecurity safeguards?\b",
            r"\bsecurity of processing\b",
            r"\binformation security\b",
        ),
    ),
    ("Section 8(3)", (r"\bsection\s*8\s*\(\s*3\s*\)\b", r"\bretention\b")),
    (
        "Section 8(4)",
        (
            r"\bsection\s*8\s*\(\s*4\s*\)\b",
            r"\baudit trail\b",
            r"\baudit log\b",
            r"\bprocessing activities\b",
        ),
    ),
    (
        "Section 8(6)",
        (
            r"\bsection\s*8\s*\(\s*6\s*\)\b",
            r"\bbreach\b",
            r"\bincident\b",
            r"\bnotification\b",
        ),
    ),
    (
        "Section 13 — Grievance Redressal",
        (
            r"\bsection\s*13\b",
            r"\bgrievance\b",
            r"\bredress(?:al)?\b",
            r"\bdpo\b",
            r"\bdata protection officer\b",
        ),
    ),
    ("Section 6", (r"\bsection\s*6\b(?!\s*\()", r"\bconsent\b")),
    ("Section 7", (r"\bsection\s*7\b", r"\blegitimate use\b")),
    (
        "Section 8",
        (
            r"\bsection\s*8\b(?!\s*\()",
            r"\bdata principal rights?\b",
            r"\berasure\b",
            r"\bdelete\b",
            r"\bdeletion\b",
        ),
    ),
    (
        "Section 9",
        (
            r"\bsection\s*9\b",
            r"\bchildren(?:'s)? data\b",
            r"\bage verification\b",
            r"\bminor\b",
        ),
    ),
    ("Section 11", (r"\bsection\s*11\b", r"\bdata portability\b", r"\bright to access\b")),
    ("Section 16", (r"\bsection\s*16\b", r"\bcross[- ]border\b", r"\btransfer\b")),
    ("Section 5", (r"\bsection\s*5\b", r"\bpurpose limitation\b", r"\bdata minimization\b")),
)


def _extract_dpdp_section_number(text: str) -> Optional[int]:
    match = re.search(r"\bsection\s*(\d+)\b", text, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def is_valid_dpdp_section(dpdp_section: str) -> bool:
    """True when the text references a real DPDP section number (1-30)."""
    n = _extract_dpdp_section_number(dpdp_section or "")
    return n is not None and 1 <= n <= 30


def closest_valid_section(dpdp_section: str) -> Optional[str]:
    """
    Best-effort remap for free-text or hallucinated section labels.

    Returns a canonical scored key when the wording strongly implies one,
    otherwise falls back to the referenced valid DPDP section number.
    """
    text = (dpdp_section or "").strip()
    if not text:
        return None

    mapped = score_section_key_from_dpdp(text)
    if mapped:
        return mapped

    lowered = text.lower()
    keyword_aliases = (
        ("Section 8(1)", ("security", "processing", "safeguard")),
        ("Section 8(4)", ("audit", "trail", "record")),
        ("Section 8(6)", ("breach", "incident", "notification")),
        ("Section 13 — Grievance Redressal", ("grievance", "redress", "dpo")),
        ("Section 11", ("portability", "access request", "export")),
        ("Section 16", ("cross-border", "cross border", "foreign transfer")),
        ("Section 6", ("consent",)),
        ("Section 6(6)", ("withdrawal", "withdraw consent")),
        ("Section 5", ("purpose limitation", "purpose", "minimization")),
    )
    for key, keywords in keyword_aliases:
        if sum(1 for word in keywords if " " not in word and word in lowered) >= 2:
            return key
        if any(phrase in lowered for phrase in keywords if " " in phrase):
            return key

    if is_valid_dpdp_section(text):
        return f"Section {_extract_dpdp_section_number(text)}"
    return None


def score_section_key_from_dpdp(dpdp_section: str) -> Optional[str]:
    """Return the canonical scoring section key, or None."""
    text = (dpdp_section or "").strip()
    if not text:
        return None

    for key, patterns in _SECTION_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return key

    match = re.search(r"\bsection\s*\d+(?:\s*\(\s*\d+\s*\))?\b", text, re.IGNORECASE)
    if not match:
        return None
    hit = match.group(0)
    for key in _SCORE_SECTION_KEYS:
        if re.search(re.escape(hit), key, re.IGNORECASE):
            return key
    return None
