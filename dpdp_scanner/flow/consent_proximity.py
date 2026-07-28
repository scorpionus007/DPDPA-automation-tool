"""
Consent-near-sink detection.

Checks whether purpose-specific consent checks exist near the sink callsite
(same function, same module) rather than just somewhere on the flow path.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

CONSENT_PATTERNS = [
    r"consent",
    r"user_consent",
    r"has_consent",
    r"check_consent",
    r"get_consent",
    r"consent_given",
    r"consent_granted",
    r"opted_in",
    r"opt_in",
    r"gdpr_consent",
    r"dpdp_consent",
    r"privacy_consent",
    r"analytics_consent",
    r"marketing_consent",
    r"tracking_consent",
]

PURPOSE_CONSENT_MAP = {
    "analytics": [r"analytics", r"tracking", r"telemetry", r"segment", r"mixpanel"],
    "marketing": [r"marketing", r"campaign", r"newsletter", r"promotional"],
}

_CONSENT_RE = re.compile(
    r"\b(" + "|".join(CONSENT_PATTERNS) + r")\b",
    re.IGNORECASE,
)


def _extract_function_blocks(content: str) -> List[Dict]:
    """Extract rough function boundaries (name, start_line, end_line, body)."""
    blocks = []
    lines = content.splitlines()
    func_re = re.compile(
        r"^(?:def|function|const|let|var|export\s+(?:default\s+)?(?:async\s+)?function"
        r"|async\s+def|async\s+function|public\s+(?:async\s+)?|private\s+(?:async\s+)?)"
        r"\s+(\w+)",
        re.IGNORECASE,
    )
    current_name: Optional[str] = None
    current_start = 0
    current_body: List[str] = []

    for i, line in enumerate(lines):
        m = func_re.match(line.strip())
        if m:
            if current_name is not None:
                blocks.append({
                    "name": current_name,
                    "start": current_start,
                    "end": i - 1,
                    "body": "\n".join(current_body),
                })
            current_name = m.group(1)
            current_start = i
            current_body = [line]
        elif current_name is not None:
            current_body.append(line)

    if current_name is not None:
        blocks.append({
            "name": current_name,
            "start": current_start,
            "end": len(lines) - 1,
            "body": "\n".join(current_body),
        })
    return blocks


def has_consent_near_sink(
    sink_content: str,
    sink_type: str,
    window_lines: int = 30,
) -> Dict:
    """
    Check whether consent patterns appear near sink call sites.

    Returns dict with:
      found: bool
      purpose_specific: bool
      consent_tokens: list of matched tokens
      proximity: "same_function" | "same_module" | "none"
    """
    if not sink_content:
        return {"found": False, "purpose_specific": False, "consent_tokens": [], "proximity": "none"}

    blocks = _extract_function_blocks(sink_content)
    purpose_patterns = PURPOSE_CONSENT_MAP.get(sink_type, [])
    purpose_re = re.compile(
        r"\b(" + "|".join(purpose_patterns) + r")\b", re.IGNORECASE
    ) if purpose_patterns else None

    for block in blocks:
        body = block["body"]
        consent_matches = _CONSENT_RE.findall(body)
        if consent_matches:
            purpose_specific = bool(purpose_re and purpose_re.search(body)) if purpose_re else False
            return {
                "found": True,
                "purpose_specific": purpose_specific,
                "consent_tokens": list(set(t.lower() for t in consent_matches)),
                "proximity": "same_function",
            }

    module_matches = _CONSENT_RE.findall(sink_content)
    if module_matches:
        purpose_specific = bool(purpose_re and purpose_re.search(sink_content)) if purpose_re else False
        return {
            "found": True,
            "purpose_specific": purpose_specific,
            "consent_tokens": list(set(t.lower() for t in module_matches)),
            "proximity": "same_module",
        }

    return {"found": False, "purpose_specific": False, "consent_tokens": [], "proximity": "none"}


def consent_proximity_score(
    sink_content: str,
    sink_type: str,
) -> float:
    """
    0.0–1.0 score for consent proximity near sink.
    Higher = consent is properly co-located with the data transfer.
    """
    result = has_consent_near_sink(sink_content, sink_type)
    if not result["found"]:
        return 0.0
    base = 0.4 if result["proximity"] == "same_module" else 0.7
    if result["purpose_specific"]:
        base += 0.3
    return min(1.0, base)
