"""
Lightweight regex-based taint tracker.

Tracks PII symbol propagation through assignments, return values, and
function arguments across files on a flow path. No AST required.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

PII_SEEDS = {
    "email", "phone", "mobile", "aadhaar", "aadhar", "pan", "name",
    "full_name", "first_name", "last_name", "password", "address",
    "dob", "date_of_birth", "ssn", "passport", "username", "user_email",
    "phone_number", "mobile_number",
}

_ASSIGN = re.compile(
    r"(?:(?:let|const|var|val)\s+)?(\w+)\s*=\s*(.*)",
    re.IGNORECASE,
)
_RETURN = re.compile(r"return\s+(.*)", re.IGNORECASE)
_FUNC_CALL = re.compile(r"(\w+)\s*\((.*?)\)", re.DOTALL)


def _tokenize(expr: str) -> Set[str]:
    return {t.lower() for t in re.findall(r"\b(\w+)\b", expr)}


def propagate_taint_in_file(
    content: str,
    incoming_taint: Set[str],
) -> Tuple[Set[str], Set[str], List[Dict]]:
    """
    Propagate taint through a single file.

    Returns:
      - outgoing_taint: symbols tainted at end of file (including via return)
      - all_tainted: every symbol that was tainted at any point
      - events: list of {line, type, symbol, source} propagation events
    """
    tainted = set(incoming_taint)
    all_tainted: Set[str] = set(incoming_taint)
    returned: Set[str] = set()
    events: List[Dict] = []

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()

        m = _ASSIGN.match(stripped)
        if m:
            target = m.group(1).lower()
            rhs_tokens = _tokenize(m.group(2))
            if rhs_tokens & tainted:
                tainted.add(target)
                all_tainted.add(target)
                events.append({
                    "line": i,
                    "type": "assignment",
                    "symbol": target,
                    "source": sorted(rhs_tokens & tainted)[:3],
                })

        m = _RETURN.match(stripped)
        if m:
            ret_tokens = _tokenize(m.group(1))
            overlap = ret_tokens & tainted
            if overlap:
                returned |= overlap
                events.append({
                    "line": i,
                    "type": "return",
                    "symbol": sorted(overlap)[:3],
                    "source": "return_statement",
                })

        for fm in _FUNC_CALL.finditer(stripped):
            func_name = fm.group(1).lower()
            arg_tokens = _tokenize(fm.group(2))
            overlap = arg_tokens & tainted
            if overlap:
                events.append({
                    "line": i,
                    "type": "call_arg",
                    "symbol": func_name,
                    "source": sorted(overlap)[:3],
                })

    outgoing = tainted | returned
    return outgoing, all_tainted, events


def trace_taint_across_path(
    flow_path: List[str],
    file_contents: Dict[str, str],
    seed_pii: Set[str] | None = None,
) -> Dict:
    """
    Trace PII taint across an ordered flow path.

    Returns:
      - reached_sink: bool (taint reached last file)
      - taint_at_sink: set of tainted symbols at sink
      - total_events: count of propagation events
      - path_events: dict of file -> events
      - confidence: 0.0–1.0
    """
    if not flow_path:
        return {"reached_sink": False, "taint_at_sink": set(), "total_events": 0, "path_events": {}, "confidence": 0.0}

    source_content = file_contents.get(flow_path[0], "")
    if seed_pii:
        current_taint = set(seed_pii)
    else:
        current_taint = set()
        for token in re.findall(r"\b(\w+)\b", source_content):
            if token.lower() in PII_SEEDS:
                current_taint.add(token.lower())

    if not current_taint:
        return {"reached_sink": False, "taint_at_sink": set(), "total_events": 0, "path_events": {}, "confidence": 0.0}

    path_events: Dict[str, List[Dict]] = {}
    total_events = 0

    for fpath in flow_path:
        content = file_contents.get(fpath, "")
        if not content:
            continue
        outgoing, _all, events = propagate_taint_in_file(content, current_taint)
        current_taint = outgoing
        if events:
            path_events[fpath] = events
            total_events += len(events)

    reached = bool(current_taint)
    confidence = 0.0
    if reached:
        confidence = min(1.0, 0.4 + 0.1 * min(total_events, 6))

    return {
        "reached_sink": reached,
        "taint_at_sink": current_taint,
        "total_events": total_events,
        "path_events": path_events,
        "confidence": round(confidence, 2),
    }
