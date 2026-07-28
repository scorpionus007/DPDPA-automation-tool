"""
Symbol-level PII tracking.

Extracts variable/field names at source and sink, checks if PII symbols
propagate through assignments and function arguments across the flow path.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

PII_SYMBOLS = {
    "email", "phone", "mobile", "aadhaar", "aadhar", "pan", "name",
    "full_name", "first_name", "last_name", "password", "address",
    "dob", "date_of_birth", "ssn", "passport", "user_name", "username",
    "phone_number", "mobile_number", "user_email", "user_id",
}

_ASSIGN_RE = re.compile(
    r"(?:^|\s)([\w.]+)\s*=\s*(?:.*?\b("
    + "|".join(re.escape(s) for s in sorted(PII_SYMBOLS))
    + r")\b)",
    re.IGNORECASE | re.MULTILINE,
)

_CALL_ARG_RE = re.compile(
    r"\w+\s*\(\s*[^)]*\b("
    + "|".join(re.escape(s) for s in sorted(PII_SYMBOLS))
    + r")\b",
    re.IGNORECASE,
)


def extract_pii_symbols(content: str) -> Set[str]:
    """Return PII-like symbol names found in code content."""
    found: Set[str] = set()
    for token in re.findall(r"\b(\w+)\b", content):
        if token.lower() in PII_SYMBOLS:
            found.add(token.lower())
    return found


def extract_pii_assignments(content: str) -> List[Tuple[str, str]]:
    """Return (target_var, pii_field) pairs from assignment statements."""
    return [(m.group(1), m.group(2).lower()) for m in _ASSIGN_RE.finditer(content)]


def extract_pii_in_call_args(content: str) -> Set[str]:
    """Return PII symbols that appear inside function call arguments."""
    return {m.group(1).lower() for m in _CALL_ARG_RE.finditer(content)}


def symbol_continuity_score(
    source_content: str,
    sink_content: str,
    path_contents: List[str],
) -> float:
    """
    Score 0.0–1.0 for how strongly PII symbols propagate source -> path -> sink.

    Checks:
    - PII symbols present at source
    - same symbols reachable through intermediary assignments
    - same symbols appear in sink call arguments
    """
    source_pii = extract_pii_symbols(source_content)
    if not source_pii:
        return 0.0

    reachable = set(source_pii)
    for content in path_contents:
        assignments = extract_pii_assignments(content)
        for target, field in assignments:
            if field in reachable:
                reachable.add(target.lower())
        reachable |= extract_pii_symbols(content) & source_pii

    sink_pii = extract_pii_symbols(sink_content)
    sink_call_pii = extract_pii_in_call_args(sink_content)

    if not sink_pii and not sink_call_pii:
        return 0.1

    overlap_symbols = reachable & (sink_pii | sink_call_pii)
    if not overlap_symbols:
        return 0.15

    call_arg_overlap = reachable & sink_call_pii
    if call_arg_overlap:
        return min(1.0, 0.5 + 0.1 * len(call_arg_overlap))

    return min(1.0, 0.3 + 0.1 * len(overlap_symbols))


def compute_symbol_evidence(
    flow_path: Dict,
    file_contents: Dict[str, str],
) -> Dict:
    """
    Compute symbol-level evidence for a flow path.
    Returns dict with score, source_pii, sink_pii, propagated symbols.
    """
    source = str(flow_path.get("source") or "")
    sink = str(flow_path.get("sink") or "")
    path = flow_path.get("path") or []

    source_content = file_contents.get(source, "")
    sink_content = file_contents.get(sink, "")
    path_contents = [file_contents.get(p, "") for p in path if p not in (source, sink)]

    score = symbol_continuity_score(source_content, sink_content, path_contents)
    source_pii = sorted(extract_pii_symbols(source_content))
    sink_pii = sorted(extract_pii_symbols(sink_content))
    sink_call_pii = sorted(extract_pii_in_call_args(sink_content))

    return {
        "symbol_continuity_score": round(score, 2),
        "source_pii_symbols": source_pii,
        "sink_pii_symbols": sink_pii,
        "sink_call_arg_pii": sink_call_pii,
    }
